// Verify the documented reconstruction contract, not full Ghidra DB equivalence.
// @category BMS46.Collaboration
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;
import java.security.MessageDigest;

public class VerifyResearch extends GhidraScript {
    Path base; int checks=0;
    List<JsonObject> rows(String name) throws Exception {
        List<JsonObject> out=new ArrayList<>();
        for(String line:Files.readAllLines(base.resolve(name+".jsonl"))) if(!line.isBlank()) out.add(JsonParser.parseString(line).getAsJsonObject());
        return out;
    }
    String s(JsonObject r,String key){return r.has(key)&&!r.get(key).isJsonNull()?r.get(key).getAsString():"";}
    Address a(String text){return toAddr(Long.parseUnsignedLong(text,16));}
    void check(boolean ok,String message){checks++;if(!ok)throw new IllegalStateException(message);}
    String normalizedType(String path){return path.replace("/pointer32","/pointer").replace(" *32"," *");}
    public void run() throws Exception {
        if(getScriptArgs().length!=2)throw new IllegalArgumentException("Snapshot and output report required");
        base=Paths.get(getScriptArgs()[0]);
        JsonObject manifest=JsonParser.parseString(Files.readString(base.resolve("manifest.json"))).getAsJsonObject();
        byte[] rom=new byte[manifest.get("rom_size").getAsInt()];
        currentProgram.getMemory().getBytes(toAddr(0),rom);
        String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(rom));
        check(hash.equals(s(manifest,"rom_sha256")),"ROM mutated or wrong input");
        check(currentProgram.getLanguageID().toString().equals(s(manifest,"language")),"Language mismatch");
        check(currentProgram.getFunctionManager().getFunctionCount()==rows("functions").size(),"Function count");
        check(currentProgram.getListing().getNumInstructions()==rows("all_instructions").size(),"Instruction count");
        for(JsonObject r:rows("memory")) {
            var b=currentProgram.getMemory().getBlock(a(s(r,"start")));
            check(b!=null && b.getName().equals(s(r,"name")) && b.getSize()==r.get("size").getAsLong() && b.isRead()==r.get("read").getAsBoolean() && b.isWrite()==r.get("write").getAsBoolean() && b.isExecute()==r.get("execute").getAsBoolean() && b.isVolatile()==r.get("volatile").getAsBoolean(),"Memory "+s(r,"name"));
        }
        for(JsonObject r:rows("functions")) {
            Function f=currentProgram.getFunctionManager().getFunctionAt(a(s(r,"address")));
            check(f!=null && f.getName().equals(s(r,"current_name")) && f.getBody().toString().equals(s(r,"body_ranges")),"Function "+s(r,"address"));
        }
        for(JsonObject r:rows("symbols")) {
            Symbol label=currentProgram.getSymbolTable().getGlobalSymbol(s(r,"name"),a(s(r,"address")));
            check(label!=null && label.getSource().toString().equals(s(r,"source")) && label.isPrimary()==r.get("primary").getAsBoolean(),"Label "+s(r,"name"));
        }
        List<String> kinds=Arrays.asList("EOL","PRE","POST","PLATE","REPEATABLE");
        for(JsonObject r:rows("comments")) check(s(r,"text").equals(currentProgram.getListing().getComment(kinds.indexOf(s(r,"type")),a(s(r,"address")))),"Comment "+s(r,"address"));
        for(JsonObject r:rows("all_instructions")) {
            Instruction i=currentProgram.getListing().getInstructionAt(a(s(r,"address")));
            check(i!=null && i.getLength()==r.get("length").getAsInt(),"Instruction "+s(r,"address"));
        }
        for(JsonObject r:rows("flow_overrides")) check(currentProgram.getListing().getInstructionAt(a(s(r,"address"))).getFlowOverride().name().equals(s(r,"override")),"Override "+s(r,"address"));
        for(JsonObject r:rows("defined_data")) {
            Data d=currentProgram.getListing().getDefinedDataAt(a(s(r,"address")));
            check(d!=null && d.getLength()==r.get("length").getAsInt() && normalizedType(d.getDataType().getPathName()).equals(normalizedType(s(r,"datatype"))),"Data "+s(r,"address")+" expected "+s(r,"datatype")+" actual "+(d==null?"none":d.getDataType().getPathName()));
        }
        for(JsonObject r:rows("datatypes")) if(s(r,"kind").equals("StructureDB")) {
            DataType t=currentProgram.getDataTypeManager().getDataType(s(r,"path"));
            check(t instanceof Structure && t.getLength()==r.get("length").getAsInt(),"Structure "+s(r,"path"));
            Structure st=(Structure)t;
            for(JsonElement e:r.getAsJsonArray("components")) {
                JsonObject c=e.getAsJsonObject(); DataTypeComponent component=st.getComponentAt(c.get("offset").getAsInt());
                check(component!=null && Objects.equals(component.getFieldName()==null?"":component.getFieldName(),s(c,"name")) && component.getLength()==c.get("length").getAsInt() && normalizedType(component.getDataType().getPathName()).equals(normalizedType(s(c,"datatype"))),"Member "+s(r,"path")+":"+s(c,"name"));
            }
        }
        for(JsonObject r:rows("bookmarks")) {
            var b=currentProgram.getBookmarkManager().getBookmark(a(s(r,"address")),s(r,"type"),s(r,"category"));
            check(b!=null && Objects.equals(b.getComment(),s(r,"comment")),"Bookmark "+s(r,"address"));
        }
        JsonObject report=new JsonObject();report.addProperty("status","PASS");report.addProperty("checks",checks);report.addProperty("rom_sha256",hash);report.addProperty("scope","Documented reconstruction contract; signatures, locals and implicit references excluded");
        Files.writeString(Paths.get(getScriptArgs()[1]),new GsonBuilder().setPrettyPrinting().create().toJson(report)+"\n");
        println("BMS46_VERIFICATION_PASS checks="+checks);
    }
}
