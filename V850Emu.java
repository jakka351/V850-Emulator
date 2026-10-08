// V850Emu.java — emulate the Mk2 FDIM startup+main-init so the computed-base init runs,
// hand-executing CALLT/CTRET (Ghidra's V850 pcode mishandles them), then dump the LIVE
// CAN signal dispatch tables (0x03FF0318 / 0x03FF03A4).
// @category FDIM
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import java.math.BigInteger;

public class V850Emu extends GhidraScript {

    long maxSteps = 8_000_000L;
    EmulatorHelper emu;

    @Override
    public void run() throws Exception {
        if (getScriptArgs().length > 0) { try { maxSteps = Long.parseLong(getScriptArgs()[0]); } catch (Exception e) {} }
        emu = new EmulatorHelper(currentProgram);

        zero(0x03FF0000L, 0x10000); zero(0x03FE0000L, 0x10000); zero(0xFFFF0000L, 0x10000);
        emu.writeMemory(toAddr(0xFFFFF6C2L), new byte[]{ 0x01 });   // clock/PLL lock bit

        emu.writeRegister(emu.getPCRegister(), BigInteger.valueOf(0x4100L));  // flash base 0x4100
        wr("sp",0x03FFEFACL); wr("gp",0x03FF7C64L); wr("tp",0x0000B4A8L);

        long[] ring = new long[96]; int ri = 0;
        long steps=0, callts=0, ctrets=0; boolean populated=false; final long CHECK=50_000L;
        println("[emu] start; maxSteps="+maxSteps+"  CTBP(init)=0x"+hex(reg("CTBP")));
        try {
            while (steps < maxSteps) {
                long p = pc(); ring[ri++ % 96] = p;
                // AFCAN peripheral model: controller acks mode/buffer requests immediately.
                // Clear the message-buffer ctrl 'busy/request' bits so write-1-wait-for-clear polls exit.
                if (p >= 0x14C00L && p <= 0x15700L) {
                    for (long n=0; n<32; n++) emu.writeMemory(toAddr(0x03FEC10EL + n*0x20L), new byte[]{0,0});
                    emu.writeMemory(toAddr(0x03FEC000L), new byte[]{0,0});   // global ctrl/status
                }
                int b0 = img8(p), b1 = img8(p+1); int hw = b0 | (b1<<8);

                // ---- CALLT imm6 : target = CTBP + u16[CTBP + imm6*2];  save ret in CTPC ----
                if ((hw & 0xFFC0) == 0x0200) {
                    int imm6 = hw & 0x3F; long ctbp = reg("CTBP");
                    long ent = img16(ctbp + imm6*2L);
                    long tgt = (ctbp + ent) & 0xFFFFFFFEL;   // mask bit0 (PC always even)
                    wr("CTPC", (p+2) & 0xFFFFFFFFL);
                    emu.writeRegister(emu.getPCRegister(), BigInteger.valueOf(tgt));
                    if (callts++ < 24) println("[emu] CALLT "+imm6+" @0x"+hex(p)+" ctbp=0x"+hex(ctbp)+" ent=0x"+hex(ent)+" -> 0x"+hex(tgt));
                    continue;
                }
                // ---- CTRET : PC = CTPC ----  (encoding 0x07E0 0x0144 => bytes E0 07 44 01)
                if (b0==0xE0 && b1==0x07 && img8(p+2)==0x44 && img8(p+3)==0x01) {
                    long ctpc = reg("CTPC");
                    emu.writeRegister(emu.getPCRegister(), BigInteger.valueOf(ctpc & 0xFFFFFFFFL));
                    ctrets++;
                    continue;
                }

                if (p < 0x4100L || (p >= 0x40000L && p < 0x03FF0000L)) { println("[emu] PC escaped: 0x"+hex(p)+" step "+steps); break; }
                if (!emu.step(monitor)) { println("[emu] step=false @"+steps+" pc=0x"+hex(pc())); break; }
                steps++;
                if (steps % CHECK == 0) {
                    long sapA=rd32(0x03FF0320L), sapB=rd32(0x03FF03ACL);
                    println("[emu] steps="+steps+" pc=0x"+hex(pc())+" callt="+callts+" ctret="+ctrets+" sapA=0x"+hex(sapA)+" sapB=0x"+hex(sapB));
                    if (looksPtr(sapA)||looksPtr(sapB)) populated=true;
                    if (populated && steps % (CHECK*6)==0) break;
                }
            }
        } catch (Throwable t) {
            println("[emu] stopped: "+t.getClass().getSimpleName()+" "+t.getMessage()+" @"+steps+" pc=0x"+hex(pc()));
        }
        StringBuilder sb=new StringBuilder();
        for (int k=0;k<96;k++){ long v=ring[(ri+k)%96]; if(v!=0) sb.append(hex(v)).append(" "); }
        println("[emu] trace: "+sb);
        println("[emu] done steps="+steps+" callt="+callts+" ctret="+ctrets+" populated="+populated+" pc=0x"+hex(pc()));

        dumpTable("TABLE A @0x03FF0318 (20B recs)", 0x03FF0318L, 20, 8);
        dumpTable("TABLE B @0x03FF03A4 (24B recs)", 0x03FF03A4L, 24, 12);
        emu.dispose();
    }

    void wr(String n,long v){ try{ emu.writeRegister(n, BigInteger.valueOf(v & 0xFFFFFFFFL)); }catch(Exception e){} }
    long reg(String n){ try{ return emu.readRegister(n).longValue() & 0xFFFFFFFFL; }catch(Exception e){ return 0; } }
    void zero(long base,int len){ emu.writeMemory(toAddr(base), new byte[len]); }
    long pc(){ return emu.readRegister(emu.getPCRegister()).longValue() & 0xFFFFFFFFL; }
    boolean looksPtr(long v){ return (v>=0x4100L && v<0x40000L) || (v>=0x03FF0000L && v<=0x03FFFFFFL); }
    String hex(long v){ return Long.toHexString(v); }
    int img8(long a){ try{ return getByte(toAddr(a)) & 0xff; }catch(Exception e){ try{ return emu.readMemory(toAddr(a),1)[0]&0xff; }catch(Exception e2){ return 0; } } }
    long img16(long a){ return img8(a) | (img8(a+1)<<8); }
    long rd32(long a){ try{ byte[] b=emu.readMemory(toAddr(a),4); return (b[0]&0xffL)|((b[1]&0xffL)<<8)|((b[2]&0xffL)<<16)|((b[3]&0xffL)<<24);}catch(Exception e){return -1;} }
    int erd8(long a){ try{ return emu.readMemory(toAddr(a),1)[0]&0xff; }catch(Exception e){ return -1; } }

    void dumpTable(String title,long base,int recSize,int maxRec){
        println("\n==== "+title+" ====");
        for (int r=0;r<maxRec;r++){
            long rec=base+(long)r*recSize;
            int k0=erd8(rec),k1=erd8(rec+1),cnt=erd8(rec+2); int len=erd8(rec+4)|(erd8(rec+5)<<8);
            long sap=rd32(rec+8);
            if (k0==0&&k1==0&&cnt==0&&sap==0) continue;
            println(String.format("  rec[%d] key=%02x %02x count=%d len=%d sap=0x%x",r,k0,k1,cnt,len,sap));
            if (!looksPtr(sap)||cnt<=0||cnt>64) continue;
            for (int s=0;s<cnt;s++){
                long e=sap+(long)s*0x10; long dp=rd32(e),dest=rd32(e+4),sz=rd32(e+8),cb=rd32(e+12);
                int off=-1,sh=-1,ln=-1; if(looksPtr(dp)){off=erd8(dp);sh=erd8(dp+1);ln=erd8(dp+2);}
                println(String.format("      sig[%d] desc=0x%x {off=%d,sh=%d,len=%d} dest=0x%x sz=%d cb=0x%x",s,dp,off,sh,ln,dest,sz,cb));
            }
        }
    }
}
