// Reconstruct the collaboration model on a NEW raw import, with analysis disabled.
// Requires the exact canonical ROM and pinned custom CPU32 language.
// @category BMS46.Collaboration
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.data.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.security.MessageDigest;

public class ImportResearch extends GhidraScript {
    Path base;
    Map<String,DataType> types = new HashMap<>();
    List<JsonObject> rows(String name) throws Exception {
        List<JsonObject> out = new ArrayList<>();
        for (String line : Files.readAllLines(base.resolve(name + ".jsonl")))
            if (!line.isBlank()) out.add(JsonParser.parseString(line).getAsJsonObject());
        return out;
    }
    String s(JsonObject row, String key) { return row.has(key) && !row.get(key).isJsonNull() ? row.get(key).getAsString() : ""; }
    Address addr(String text) { return toAddr(Long.parseUnsignedLong(text, 16)); }
    DataType dtype(String path) {
        if (types.containsKey(path)) return types.get(path);
        DataType found = currentProgram.getDataTypeManager().getDataType(path);
        if (found != null) return found;
        Matcher array = Pattern.compile("(.+)\\[(\\d+)\\]").matcher(path);
        if (array.matches()) {
            DataType element = dtype(array.group(1));
            return new ArrayDataType(element, Integer.parseInt(array.group(2)), element.getLength());
        }
        if (path.endsWith(" *32") || path.endsWith(" *")) return new PointerDataType(dtype(path.substring(0, path.lastIndexOf(" *"))), 4);
        switch (path) {
            case "/byte": return ByteDataType.dataType;
            case "/uchar": return UnsignedCharDataType.dataType;
            case "/ushort": return UnsignedShortDataType.dataType;
            case "/uint": return UnsignedIntegerDataType.dataType;
            case "/dword": return DWordDataType.dataType;
            case "/undefined": return DataType.DEFAULT;
            case "/undefined1": return Undefined1DataType.dataType;
            case "/undefined2": return Undefined2DataType.dataType;
            case "/undefined4": return Undefined4DataType.dataType;
            case "/void": return VoidDataType.dataType;
            case "/string": return StringDataType.dataType;
            case "/pointer": return new PointerDataType(null, 4);
            default: throw new IllegalArgumentException("Unsupported type: " + path);
        }
    }
    public void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("Path to annotations/q28g required");
        base = Paths.get(getScriptArgs()[0]);
        byte[] rom = new byte[262144];
        if (currentProgram.getMemory().getBytes(toAddr(0), rom) != rom.length) throw new IllegalStateException("Full ROM required");
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(rom));
        if (!hash.equals("d3c3abb5236240906a9d8851b31802e0751c233ebe0bba58d2c51f66e137679d")) throw new IllegalStateException("Canonical SHA mismatch");
        if (!currentProgram.getLanguageID().toString().equals("68000:BE:32:CPU32_STATUS_V2")) throw new IllegalStateException("Exact research language required");
        if (currentProgram.getFunctionManager().getFunctionCount() != 0 || currentProgram.getListing().getNumInstructions() != 0) throw new IllegalStateException("Use a NEW raw import with auto-analysis disabled");
        for (JsonObject r : rows("memory")) {
            Address a = addr(s(r,"start"));
            MemoryBlock b = currentProgram.getMemory().getBlock(a);
            if (b == null) b = currentProgram.getMemory().createUninitializedBlock(s(r,"name"), a, r.get("size").getAsLong(), false);
            if (b.getSize() != r.get("size").getAsLong()) throw new IllegalStateException("Memory layout mismatch");
            b.setName(s(r,"name")); b.setRead(r.get("read").getAsBoolean()); b.setWrite(r.get("write").getAsBoolean());
            b.setExecute(r.get("execute").getAsBoolean()); b.setVolatile(r.get("volatile").getAsBoolean());
        }
        AddressSet restricted = new AddressSet();
        for (JsonObject r : rows("all_instructions")) { Address a = addr(s(r,"address")); restricted.addRange(a,a.add(r.get("length").getAsInt()-1)); }
        for (JsonObject r : rows("all_instructions")) {
            monitor.checkCancelled(); Address a = addr(s(r,"address"));
            if (currentProgram.getListing().getInstructionAt(a) == null) new DisassembleCommand(a,restricted,true).applyTo(currentProgram,monitor);
            Instruction i = currentProgram.getListing().getInstructionAt(a);
            if (i == null || i.getLength() != r.get("length").getAsInt()) throw new IllegalStateException("Decode mismatch at " + a);
        }
        for (JsonObject r : rows("flow_overrides")) currentProgram.getListing().getInstructionAt(addr(s(r,"address"))).setFlowOverride(FlowOverride.valueOf(s(r,"override")));
        Pattern ranges = Pattern.compile("\\[([0-9a-fA-F]+), ([0-9a-fA-F]+)\\]");
        for (JsonObject r : rows("functions")) {
            AddressSet body = new AddressSet(); Matcher m = ranges.matcher(s(r,"body_ranges"));
            while (m.find()) body.addRange(addr(m.group(1)),addr(m.group(2)));
            Function f = currentProgram.getFunctionManager().createFunction(s(r,"current_name"),addr(s(r,"address")),body,SourceType.valueOf(s(r,"source")));
            if (r.has("comment")) f.setComment(s(r,"comment"));
            if (r.has("repeatable_comment")) f.setRepeatableComment(s(r,"repeatable_comment"));
            f.setNoReturn(r.get("no_return").getAsBoolean());
        }
        for (JsonObject r : rows("symbols")) {
            Address a=addr(s(r,"address"));
            Symbol label=currentProgram.getSymbolTable().createLabel(a,s(r,"name"),SourceType.valueOf(s(r,"source")));
            if (r.get("primary").getAsBoolean()) label.setPrimary();
        }
        // Build structure shells first so pointers and nested types can refer forward.
        for (JsonObject r : rows("datatypes")) if (s(r,"kind").equals("StructureDB")) {
            String path=s(r,"path"); int slash=path.lastIndexOf('/');
            StructureDataType t=new StructureDataType(new CategoryPath(path.substring(0,slash)),path.substring(slash+1),r.get("length").getAsInt());
            t.setDescription(s(r,"description")); types.put(path,t);
        }
        for (JsonObject r : rows("datatypes")) if (s(r,"kind").equals("StructureDB")) {
            Structure t=(Structure)types.get(s(r,"path"));
            for (JsonElement component : r.getAsJsonArray("components")) {
                JsonObject c=component.getAsJsonObject();
                t.replaceAtOffset(c.get("offset").getAsInt(),dtype(s(c,"datatype")),c.get("length").getAsInt(),s(c,"name"),s(c,"comment"));
            }
        }
        for (JsonObject r : rows("datatypes")) {
            String path=s(r,"path"); types.put(path,currentProgram.getDataTypeManager().resolve(dtype(path),DataTypeConflictHandler.DEFAULT_HANDLER));
        }
        for (JsonObject r : rows("defined_data")) {
            DataUtilities.createData(currentProgram,addr(s(r,"address")),dtype(s(r,"datatype")),r.get("length").getAsInt(),false,DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
        }
        String[] kinds={"EOL","PRE","POST","PLATE","REPEATABLE"};
        for (JsonObject r : rows("comments")) for (int k=0;k<kinds.length;k++) if (kinds[k].equals(s(r,"type"))) currentProgram.getListing().setComment(addr(s(r,"address")),k,s(r,"text"));
        for (JsonObject r : rows("bookmarks")) currentProgram.getBookmarkManager().setBookmark(addr(s(r,"address")),s(r,"type"),s(r,"category"),s(r,"comment"));
        // A separate verifier must run before the CLI reports success.
        println("BMS46_IMPORT_COMPLETE: functions, global labels, comments, data, structures and flow overrides restored. Function signatures/local variables remain reference-only metadata; see docs/RECONSTRUCTION.md.");
    }
}
