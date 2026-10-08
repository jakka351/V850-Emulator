// V850Emu.java — emulate the Mk2 FDIM startup so the computed-base init runs,
// then dump the LIVE CAN signal dispatch tables (0x03FF0318 / 0x03FF03A4) and
// walk each 16-byte signal entry {descPtr, destRAM, sizeType, cb} -> descriptor {off,shift,len}.
// @category FDIM
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.address.Address;
import java.math.BigInteger;

public class V850Emu extends GhidraScript {

    long maxSteps = 6_000_000L;

    @Override
    public void run() throws Exception {
        String arg0 = (getScriptArgs().length > 0) ? getScriptArgs()[0] : null;
        if (arg0 != null) { try { maxSteps = Long.parseLong(arg0); } catch (Exception e) {} }

        final EmulatorHelper emu = new EmulatorHelper(currentProgram);
        final long IMG_LO = 0x0, IMG_HI = 0x3BF00;

        // Zero-fill every uninitialized read (RAM + SFRs), allow writes anywhere (sparse state).
        emu.getEmulator().setMemoryFaultHandler(new MemoryFaultHandler() {
            public boolean uninitializedRead(Address address, int size, byte[] buf, int bufOffset) {
                for (int i = 0; i < size; i++) buf[bufOffset + i] = 0;
                return true; // handled: treat as 0
            }
            public boolean unknownAddress(Address address, boolean write) {
                return true; // allow
            }
        });

        Address entry = toAddr(0x0);
        emu.writeRegister(emu.getPCRegister(), BigInteger.ZERO);
        // startup sets these itself, but seed them so an early fault can't derail us:
        try { emu.writeRegister("sp", BigInteger.valueOf(0x03FFEFACL)); } catch (Exception e) {}
        try { emu.writeRegister("gp", BigInteger.valueOf(0x03FF7C64L)); } catch (Exception e) {}
        try { emu.writeRegister("tp", BigInteger.valueOf(0x0000B4A8L)); } catch (Exception e) {}

        println("[emu] start PC=0x0  maxSteps=" + maxSteps);
        long steps = 0; long lastPc = -1; boolean populated = false;
        long CHECK = 200_000L;
        try {
            while (steps < maxSteps) {
                if (!emu.step(monitor)) {
                    println("[emu] step returned false at step " + steps + " pc=0x" + Long.toHexString(pc(emu)));
                    break;
                }
                steps++;
                if (steps % CHECK == 0) {
                    long p = pc(emu);
                    long v318 = rd32(emu, 0x03FF0320L); // sigArrayPtr of record0 in table A
                    long v3a4 = rd32(emu, 0x03FF03ACL); // sigArrayPtr of record0 in table B
                    println("[emu] steps=" + steps + " pc=0x" + Long.toHexString(p)
                            + " [0x3ff0320]=0x" + Long.toHexString(v318)
                            + " [0x3ff03ac]=0x" + Long.toHexString(v3a4));
                    if (looksPtr(v318) || looksPtr(v3a4)) { populated = true; }
                    // once populated AND we've run a bit more to let all records fill, stop
                    if (populated && steps % (CHECK*4) == 0) break;
                    // guard: PC escaped into RAM/SFR for a long time => likely wedged
                    lastPc = p;
                }
            }
        } catch (Throwable t) {
            println("[emu] stopped by exception at step " + steps + ": " + t.getClass().getSimpleName() + " " + t.getMessage());
        }
        println("[emu] done. steps=" + steps + " populated=" + populated);

        dumpTable(emu, "TABLE A @0x03FF0318 (20-byte records)", 0x03FF0318L, 20, 8);
        dumpTable(emu, "TABLE B @0x03FF03A4 (24-byte records)", 0x03FF03A4L, 24, 11);

        emu.dispose();
    }

    long pc(EmulatorHelper emu) { return emu.readRegister(emu.getPCRegister()).longValue(); }

    boolean looksPtr(long v) {
        return (v >= 0x100 && v < 0x3BF00) || (v >= 0x03FF0000L && v <= 0x03FFFFFFL);
    }

    long rd32(EmulatorHelper emu, long addr) {
        try {
            byte[] b = emu.readMemory(toAddr(addr), 4);
            return ((b[0]&0xffL)) | ((b[1]&0xffL)<<8) | ((b[2]&0xffL)<<16) | ((b[3]&0xffL)<<24);
        } catch (Exception e) { return -1; }
    }
    int rd8(EmulatorHelper emu, long addr) {
        try { return emu.readMemory(toAddr(addr),1)[0] & 0xff; } catch (Exception e) { return -1; }
    }

    void dumpTable(EmulatorHelper emu, String title, long base, int recSize, int maxRec) {
        println("\n==== " + title + " ====");
        for (int r = 0; r < maxRec; r++) {
            long rec = base + (long)r * recSize;
            int key0 = rd8(emu, rec+0), key1 = rd8(emu, rec+1), cnt = rd8(emu, rec+2);
            int len  = rd8(emu, rec+4) | (rd8(emu, rec+5)<<8);
            long sap = rd32(emu, rec+8);
            if (key0==0 && key1==0 && cnt==0 && sap==0) continue;
            println(String.format("  rec[%d] key=%02x %02x  count=%d  len=%d  sigArrayPtr=0x%x",
                    r, key0, key1, cnt, len, sap));
            if (!looksPtr(sap) || cnt<=0 || cnt>64) continue;
            for (int s = 0; s < cnt; s++) {
                long e = sap + (long)s*0x10;
                long dp = rd32(emu, e+0), dest = rd32(emu, e+4); long sz = rd32(emu, e+8), cb = rd32(emu, e+12);
                int off=-1, sh=-1, ln=-1;
                if (looksPtr(dp)) { off=rd8(emu,dp); sh=rd8(emu,dp+1); ln=rd8(emu,dp+2); }
                println(String.format("      sig[%d] desc=0x%x {off=%d,sh=%d,len=%d}  dest=0x%x  sz=%d  cb=0x%x",
                        s, dp, off, sh, ln, dest, sz, cb));
            }
        }
    }
}
