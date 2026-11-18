// Export analysis-only flow overrides. No firmware bytes are emitted.
// @category BMS46.Collaboration
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import com.google.gson.*;
import java.nio.file.*;
public class ExportFlowOverrides extends GhidraScript {
    public void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("Output JSON path required");
        JsonArray rows = new JsonArray();
        for (Instruction i : currentProgram.getListing().getInstructions(true)) {
            if (i.getFlowOverride() == FlowOverride.NONE) continue;
            JsonObject r = new JsonObject();
            r.addProperty("address", i.getAddress().toString());
            r.addProperty("override", i.getFlowOverride().name()); rows.add(r);
        }
        Files.writeString(Paths.get(getScriptArgs()[0]), new GsonBuilder().setPrettyPrinting().create().toJson(rows) + "\n");
        println("Exported " + rows.size() + " flow overrides");
    }
}
