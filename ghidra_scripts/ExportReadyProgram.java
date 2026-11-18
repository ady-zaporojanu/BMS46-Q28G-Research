// Package the ACTUAL annotated program, including ROM and full database state.
// This is a release/review asset, not the firmware-free text snapshot.
// @category BMS46.Collaboration
import ghidra.app.script.GhidraScript;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.HexFormat;
public class ExportReadyProgram extends GhidraScript {
    public void run() throws Exception {
        if(getScriptArgs().length!=1)throw new IllegalArgumentException("New output .gzf path required");
        Path out=Paths.get(getScriptArgs()[0]);
        if(Files.exists(out))throw new IllegalStateException("Refusing overwrite");
        byte[] rom=new byte[262144];
        currentProgram.getMemory().getBytes(toAddr(0),rom);
        String sha=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(rom));
        if(!sha.equals("d3c3abb5236240906a9d8851b31802e0751c233ebe0bba58d2c51f66e137679d"))throw new IllegalStateException("Wrong canonical ROM");
        Files.createDirectories(out.getParent());
        currentProgram.getDomainFile().packFile(out.toFile(),monitor);
        println("BMS46_READY_PROGRAM_PACKED " + out.getFileName());
    }
}
