// PRIVATE EXPORT: emits firmware bytes and complete disassembly. Never commit its output.
// Read-only inventory, used as input to tools/snapshot.py; not a database backup.
// @category BMS46.Research
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.block.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.mem.MemoryBlock;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;

public class ExportPrivateEvidence extends GhidraScript {
    Gson gson=new GsonBuilder().disableHtmlEscaping().create();
    Path dir;
    Map<String,Object> row(Object... kv) {
        Map<String,Object> m=new LinkedHashMap<>();
        for(int i=0;i<kv.length;i+=2)m.put(kv[i].toString(),kv[i+1]);
        return m;
    }
    String a(Address x) { return x==null?null:x.toString(); }
    String hex(byte[] bs) { return HexFormat.of().formatHex(bs); }
    PrintWriter writer(String name) throws Exception {
        return new PrintWriter(Files.newBufferedWriter(dir.resolve(name+".jsonl"),StandardCharsets.UTF_8));
    }
    void emit(PrintWriter w,Object obj) {w.println(gson.toJson(obj));}
    String region(Address addr) {
        if(addr==null||!addr.isMemoryAddress())return "OTHER";
        MemoryBlock b=currentProgram.getMemory().getBlock(addr);
        long n=addr.getOffset();
        // This is a classification heuristic, not a verified peripheral identity.
        if(n>=0xfff000L&&n<=0xffffffL)return "MMIO_CANDIDATE";
        if(b!=null)return b.isInitialized()?"ROM_OR_INITIALIZED":"RAM_OR_UNINITIALIZED";
        return "UNMAPPED";
    }
    String norm(Instruction ins) {
        List<String> ops=new ArrayList<>();
        for(int i=0;i<ins.getNumOperands();i++) {
            List<String> parts=new ArrayList<>();
            for(Object o:ins.getOpObjects(i)) {
                if(o instanceof Register)parts.add(((Register)o).getName());
                else if(o instanceof Address) {
                    Address ad=(Address)o;
                    parts.add(ins.getFlowType().isCall()?"CALL_TARGET":
                        ins.getFlowType().isJump()?"BRANCH_TARGET":region(ad));
                } else if(o instanceof Scalar) {
                    Scalar sc=(Scalar)o;
                    parts.add("IMM"+sc.bitLength()+":"+Long.toUnsignedString(sc.getUnsignedValue(),16));
                } else parts.add(o.toString());
            }
            ops.add(ins.getOperandType(i)+":"+String.join("/",parts));
        }
        return ins.getMnemonicString()+" "+String.join(",",ops);
    }
    @Override public void run() throws Exception {
        if(getScriptArgs().length!=1)throw new IllegalArgumentException("output_directory required");
        dir=Paths.get(getScriptArgs()[0]).resolve(currentProgram.getDomainFile().getPathname().replaceAll("[^A-Za-z0-9_.-]","_"));
        Files.createDirectories(dir);
        Listing li=currentProgram.getListing();
        FunctionManager fm=currentProgram.getFunctionManager();
        try(PrintWriter w=writer("program")) {
            emit(w,row("name",currentProgram.getName(),"domain_path",currentProgram.getDomainFile().getPathname(),
                "sha256",currentProgram.getExecutableSHA256(),"md5",currentProgram.getExecutableMD5(),
                "language",currentProgram.getLanguageID().toString(),"big_endian",currentProgram.getLanguage().isBigEndian(),
                "image_base",a(currentProgram.getImageBase()),"function_count",fm.getFunctionCount(),
                "export_mode","READ_ONLY_NO_ANALYSIS","schema_version",2));
        }
        try(PrintWriter w=writer("memory")) {
            for(MemoryBlock b:currentProgram.getMemory().getBlocks())emit(w,row("name",b.getName(),"start",a(b.getStart()),"end",a(b.getEnd()),"size",b.getSize(),
                "read",b.isRead(),"write",b.isWrite(),"execute",b.isExecute(),"volatile",b.isVolatile(),"initialized",b.isInitialized(),"source",b.getSourceName(),"comment",b.getComment()));
        }
        try(PrintWriter w=writer("symbols")) {
            SymbolIterator it=currentProgram.getSymbolTable().getAllSymbols(true);
            while(it.hasNext()){monitor.checkCancelled();Symbol s=it.next();emit(w,row("address",a(s.getAddress()),"name",s.getName(),"qualified_name",s.getName(true),
                "namespace",s.getParentNamespace().getName(true),"source",s.getSource().toString(),"type",s.getSymbolType().toString(),"primary",s.isPrimary(),"dynamic",s.isDynamic()));}
        }
        try(PrintWriter w=writer("comments")) {
            String[] kinds={"EOL","PRE","POST","PLATE","REPEATABLE"};
            for(int k=0;k<kinds.length;k++) {
                AddressIterator it=li.getCommentAddressIterator(k,currentProgram.getMemory(),true);
                while(it.hasNext()){Address ad=it.next();emit(w,row("address",a(ad),"type",kinds[k],"text",li.getComment(k,ad)));}
            }
        }
        try(PrintWriter w=writer("bookmarks")) {
            Iterator<Bookmark> it=currentProgram.getBookmarkManager().getBookmarksIterator();
            while(it.hasNext()){Bookmark b=it.next();emit(w,row("address",a(b.getAddress()),"type",b.getTypeString(),"category",b.getCategory(),"comment",b.getComment()));}
        }
        try(PrintWriter w=writer("defined_data")) {
            DataIterator it=li.getDefinedData(true);
            while(it.hasNext()){Data d=it.next();emit(w,row("address",a(d.getAddress()),"end",a(d.getMaxAddress()),"length",d.getLength(),"datatype",d.getDataType().getPathName(),
                "representation",d.getDefaultValueRepresentation(),"components",d.getNumComponents()));}
        }
        try(PrintWriter w=writer("datatypes")) {
            Iterator<DataType> it=currentProgram.getDataTypeManager().getAllDataTypes();
            while(it.hasNext()) {
                DataType d=it.next();List<Object> cs=new ArrayList<>();
                if(d instanceof Composite)for(DataTypeComponent c:((Composite)d).getComponents())cs.add(row("ordinal",c.getOrdinal(),"offset",c.getOffset(),"length",c.getLength(),"name",c.getFieldName(),"datatype",c.getDataType().getPathName(),"comment",c.getComment()));
                emit(w,row("path",d.getPathName(),"kind",d.getClass().getSimpleName(),"length",d.getLength(),"description",d.getDescription(),"components",cs,"definition",d.toString()));
            }
        }
        BasicBlockModel model=new BasicBlockModel(currentProgram);
        try(PrintWriter fw=writer("functions");PrintWriter iw=writer("instructions");PrintWriter rw=writer("references");PrintWriter cw=writer("calls")) {
            FunctionIterator it=fm.getFunctions(true);
            while(it.hasNext()) {
                monitor.checkCancelled();Function f=it.next();
                List<Object> instructions=new ArrayList<>(),blocks=new ArrayList<>(),vars=new ArrayList<>();
                List<String> normalized=new ArrayList<>(),callers=new ArrayList<>(),callees=new ArrayList<>();
                Set<String> constants=new TreeSet<>(),ram=new TreeSet<>(),rom=new TreeSet<>(),mmio=new TreeSet<>();
                ByteArrayOutputStream bytes=new ByteArrayOutputStream();
                for(Function c:f.getCallingFunctions(monitor))callers.add(a(c.getEntryPoint()));
                for(Function c:f.getCalledFunctions(monitor))callees.add(a(c.getEntryPoint()));
                // Function APIs expose sets; stabilize JSON without changing edges.
                Collections.sort(callers);Collections.sort(callees);
                for(Variable v:f.getAllVariables())vars.add(row("name",v.getName(),"datatype",v.getDataType().getPathName(),"storage",v.getVariableStorage().toString(),"comment",v.getComment(),"source",v.getSource().toString()));
                InstructionIterator ii=li.getInstructions(f.getBody(),true);
                while(ii.hasNext()) {
                    Instruction ins=ii.next();String n=norm(ins);normalized.add(n);bytes.write(ins.getBytes());
                    emit(iw,row("function",a(f.getEntryPoint()),"address",a(ins.getAddress()),"length",ins.getLength(),"bytes",hex(ins.getBytes()),"mnemonic",ins.getMnemonicString(),"text",ins.toString(),"normalized",n,"flow_type",ins.getFlowType().toString()));
                    for(int op=0;op<ins.getNumOperands();op++)for(Object o:ins.getOpObjects(op))if(o instanceof Scalar)constants.add(((Scalar)o).bitLength()+":"+Long.toUnsignedString(((Scalar)o).getUnsignedValue(),16));
                    for(Reference r:ins.getReferencesFrom()) {
                        String rg=region(r.getToAddress()), dest=a(r.getToAddress());
                        emit(rw,row("function",a(f.getEntryPoint()),"from",a(r.getFromAddress()),"to",dest,"type",r.getReferenceType().toString(),"read",r.getReferenceType().isRead(),"write",r.getReferenceType().isWrite(),"operand",r.getOperandIndex(),"region",rg));
                        if(r.getReferenceType().isData()){
                            if(rg.startsWith("RAM"))ram.add(dest);if(rg.startsWith("ROM"))rom.add(dest);if(rg.startsWith("MMIO"))mmio.add(dest);
                        }
                        if(r.getReferenceType().isCall())emit(cw,row("caller",a(f.getEntryPoint()),"site",a(ins.getAddress()),"callee",dest,"type",r.getReferenceType().toString(),"resolved_function",fm.getFunctionAt(r.getToAddress())!=null));
                    }
                }
                CodeBlockIterator bi=model.getCodeBlocksContaining(f.getBody(),monitor);int edgeCount=0,backEdges=0;
                while(bi.hasNext()) {
                    CodeBlock b=bi.next();List<Object> edges=new ArrayList<>();
                    CodeBlockReferenceIterator ei=b.getDestinations(monitor);
                    while(ei.hasNext()) {CodeBlockReference e=ei.next();boolean internal=f.getBody().contains(e.getDestinationAddress());
                        edges.add(row("to",a(e.getDestinationAddress()),"type",e.getFlowType().toString(),"internal",internal));
                        if(internal){edgeCount++;if(e.getDestinationAddress().compareTo(b.getFirstStartAddress())<=0)backEdges++;}
                    }
                    blocks.add(row("start",a(b.getFirstStartAddress()),"end",a(b.getMaxAddress()),"flow",b.getFlowType().toString(),"edges",edges));
                }
                emit(fw,row("address",a(f.getEntryPoint()),"end",a(f.getBody().getMaxAddress()),"body_ranges",f.getBody().toString(),"size",f.getBody().getNumAddresses(),
                    "current_name",f.getName(),"namespace",f.getParentNamespace().getName(true),"source",f.getSymbol().getSource().toString(),"prototype",f.getPrototypeString(true,true),
                    "signature_source",f.getSignatureSource().toString(),"is_thunk",f.isThunk(),"no_return",f.hasNoReturn(),"comment",f.getComment(),"repeatable_comment",f.getRepeatableComment(),
                    "variables",vars,"instruction_count",normalized.size(),"normalized_instructions",normalized,"instruction_bytes",hex(bytes.toByteArray()),"blocks",blocks,
                    "internal_edges",edgeCount,"backward_edges_approx",backEdges,"complexity_E_minus_N_plus_2",edgeCount-blocks.size()+2,
                    "callers",callers,"callees",callees,"constants",constants,"RAM_refs",ram,"ROM_refs",rom,"MMIO_refs",mmio,
                    "limitations","Static explicit references only; indirect accesses and unresolved calls incomplete; complexity assumes connected CFG; memory class is heuristic."));
            }
        }

        try(PrintWriter iw=writer("all_instructions");PrintWriter rw=writer("all_references")) {
            InstructionIterator all=li.getInstructions(true);
            while(all.hasNext()) {
                monitor.checkCancelled(); Instruction ins=all.next(); Function f=fm.getFunctionContaining(ins.getAddress());
                emit(iw,row("address",a(ins.getAddress()),"length",ins.getLength(),"bytes",hex(ins.getBytes()),"text",ins.toString(),"mnemonic",ins.getMnemonicString(),"function",f==null?null:a(f.getEntryPoint())));
            }
            AddressIterator ai=currentProgram.getReferenceManager().getReferenceSourceIterator(currentProgram.getMemory(),true);
            while(ai.hasNext())for(Reference r:currentProgram.getReferenceManager().getReferencesFrom(ai.next()))emit(rw,row("from",a(r.getFromAddress()),"to",a(r.getToAddress()),"type",r.getReferenceType().toString(),"source",r.getSource().toString(),"operand",r.getOperandIndex()));
        }
        byte[] rom=new byte[262144];
        int copied=currentProgram.getMemory().getBytes(toAddr(0),rom);
        if(copied!=rom.length)throw new IllegalStateException("ROM readback incomplete");
        Files.write(dir.resolve("rom_readback.bin"),rom);
        println("BMS46_READ_ONLY_SNAPSHOT_COMPLETE "+dir);
    }
}
