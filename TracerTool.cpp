#define _FILE_OFFSET_BITS  64
#include <stdio.h>
#include "pin.H"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <iostream>
#include <fstream>
#include <memory>

template <typename I> std::string n2hexstr(I w, size_t hex_len = sizeof(I)<<1) {
    static const char* digits = "0123456789ABCDEF";
    std::string rc(hex_len,'0');
    for (size_t i=0, j=(hex_len-1)*4 ; i<hex_len; ++i,j-=4)
        rc[i] = digits[(w>>j) & 0x0f];
    return rc;
}

class BBData {
    public:
    std::string module;
    std::vector<uint8_t> bytes;
    std::string disasm;
    bool dynamic = false;
    tr1::unordered_map<uint32_t,uint64_t> lcathist;
};

std::vector<BBData*> bblmap;
tr1::unordered_set<std::string> modulefilter;

tr1::unordered_map<uint32_t,uint64_t> cathist;
tr1::unordered_map<uint32_t,uint64_t> dyncathist;
tr1::unordered_map<uint32_t,uint64_t> markcathist;
tr1::unordered_map<uint32_t,uint64_t> markcatdynhist;

uint64_t outsize=0;

enum class OpMode { measure, trace };
OpMode mode = OpMode::measure;

bool add_addr = false;
bool mark_trace = false;

FILE * tracefile=NULL;
FILE * modfile=NULL;

inline bool ends_with(std::string const & value, std::string const & ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

int _enableTrace() {
    mark_trace=true;
    LOG("Mark called\n");
    return 1;
}

int _disableTrace() {
    mark_trace=false;
    LOG("Unmark called\n");
    return 2;
}

VOID _measure(BBData *insn) {
    outsize+=insn->disasm.size();
    if(mark_trace) {
		for(auto cat:insn->lcathist) {
			markcathist[cat.first]+=cat.second;
        }
    }else {
        for(auto cat:insn->lcathist) {
            cathist[cat.first]+=cat.second;
        }
    }
 
}

VOID _measure_dyn(BBData *insn) {
    outsize+=insn->disasm.size();
    if(mark_trace) {
		for(auto cat:insn->lcathist) {
			markcatdynhist[cat.first]+=cat.second;
        }
	}else {
        for(auto cat:insn->lcathist) {
			dyncathist[cat.first]+=cat.second;
        }
    }
}

VOID _trace(BBData *insn) {
    outsize+=insn->disasm.size();
	fwrite(insn->disasm.c_str() , sizeof(char), insn->disasm.size(), tracefile);
    if(mark_trace) {
		for(auto cat:insn->lcathist) {
			markcathist[cat.first]+=cat.second;
        }
    }else {
        for(auto cat:insn->lcathist) {
            cathist[cat.first]+=cat.second;
        }
    }
 
}

VOID _trace_dyn(BBData *insn) {
    outsize+=insn->disasm.size();
	fwrite(insn->disasm.c_str() , sizeof(char), insn->disasm.size(), tracefile);
    if(mark_trace) {
		for(auto cat:insn->lcathist) {
			markcatdynhist[cat.first]+=cat.second;
        }
	}else {
        for(auto cat:insn->lcathist) {
			dyncathist[cat.first]+=cat.second;
        }
    }
}

VOID ImageLoad(IMG img, VOID *v)
{
    fprintf(modfile,"%s\n", IMG_Name(img).c_str());
    RTN enableRtn = RTN_FindByName(img, "enableTrace");
    if (RTN_Valid(enableRtn))
    {
       RTN_Replace(enableRtn,(AFUNPTR)_enableTrace);
       LOG("Replaced enable in "+IMG_Name(img)+"\n");
    }

    RTN disableRtn = RTN_FindByName(img, "disableTrace");
    if (RTN_Valid(disableRtn))
    {
        RTN_Replace(disableRtn,(AFUNPTR)_disableTrace);
        LOG("Replaced disable in "+IMG_Name(img)+"\n");
    }

    RTN enableRtnJ = RTN_FindByName(img,"Java_org_jaka_Native_enableTrace");
    if (RTN_Valid(enableRtnJ))
    {
        RTN_Replace(enableRtnJ,(AFUNPTR)_enableTrace);
        LOG("Replaced JNI enable in "+IMG_Name(img)+"\n");
    }
    RTN disableRtnJ = RTN_FindByName(img,"Java_org_jaka_Native_disableTrace");
    if (RTN_Valid(disableRtnJ))
    {
        RTN_Replace(disableRtnJ,(AFUNPTR)_disableTrace);
        LOG("Replaced JNI disable in "+IMG_Name(img)+"\n");
    }
}

VOID Trace(TRACE trc, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        BBData* the_bb = new BBData();
        IMG image = IMG_FindByAddress(BBL_Address(bbl));
        if(IMG_Valid(image)) {
            the_bb->module = IMG_Name(image);
		    //printf("BBL at %p RVA(%p) size %d in image %s loaded at %p\n",BBL_Address(bbl),BBL_Address(bbl)-IMG_LowAddress(image),BBL_Size(bbl),IMG_Name(image).c_str(),IMG_LowAddress(image));
        }else {
            the_bb->module = "UNKNOWN";
            the_bb->dynamic = true;
            //printf("BBL at %p size %d in unknown image\n",BBL_Address(bbl),BBL_Size(bbl));
        }
        if(modulefilter.count(the_bb->module)==0) {
            if(the_bb->dynamic) {
                BBL_InsertCall(bbl, IPOINT_BEFORE, mode == OpMode::measure ? (AFUNPTR)_measure_dyn : (AFUNPTR)_trace_dyn, IARG_UINT64, the_bb, IARG_END);
            }else {
                BBL_InsertCall(bbl, IPOINT_BEFORE, mode == OpMode::measure ? (AFUNPTR)_measure : (AFUNPTR)_trace , IARG_UINT64, the_bb, IARG_END);
            }
            
            for( INS ins= BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
                if(add_addr) {
                    the_bb->disasm.append(n2hexstr(INS_Address(ins))+' ');
                }
                the_bb->disasm.append(INS_Disassemble(ins)+'\n');
                the_bb->lcathist[INS_Category(ins)]++;
            }

            the_bb->bytes = std::vector<uint8_t>((uint8_t*)BBL_Address(bbl),((uint8_t*)BBL_Address(bbl))+BBL_Size(bbl));
            bblmap.push_back(the_bb);
        }
	 }
}

VOID Fini(INT32 code, VOID *v)
{
    LOG("Trace size would be "+decstr(outsize)+" bytes\n");
	
   if(tracefile != NULL) {
       LOG("Closing trace file\n");
       fclose(tracefile);
   }
   if(modfile != NULL) {
       fclose(modfile);
   }
   
   uint64_t totalinsns = 0;
   uint64_t totalmarkinsns = 0;
   uint64_t totaldynamicins = 0;
   uint64_t totalmarkdynamicins = 0;

   LOG("UNMARKED STATIC CODE\n");
   for ( int cats = XED_CATEGORY_INVALID; cats != XED_CATEGORY_LAST; cats++ ) {
       LOG( "   " + CATEGORY_StringShort(cats) + ": "+decstr(cathist[cats])+"\n");
       totalinsns += cathist[cats];
   }
   LOG("   TOTAL COUNT STATIC: "+decstr(totalinsns)+"\n\n");
   LOG("MARKED STATIC CODE\n");
   for ( int cats = XED_CATEGORY_INVALID; cats != XED_CATEGORY_LAST; cats++ ) {
       LOG( "   " + CATEGORY_StringShort(cats) + ": "+decstr(markcathist[cats])+"\n");
       totalmarkinsns += markcathist[cats];
   }
   LOG("   TOTAL COUNT MARKED STATIC: "+decstr(totalmarkinsns)+"\n\n");
   if(dyncathist.size() != 0) {
      LOG("RUNTIME GENERATED CODE:\n");
      for ( int cats = XED_CATEGORY_INVALID; cats != XED_CATEGORY_LAST; cats++ ) {
         LOG( "   " + CATEGORY_StringShort(cats) + ": "+ decstr(dyncathist[cats]) +"\n");
         totaldynamicins += dyncathist[cats];
      }
      LOG("   TOTAL DYNAMIC COUNT: "+decstr(totaldynamicins)+"\n\n");
   }else {
       LOG("NO DYNAMIC CODE EXECUTED\n\n");
   }

   if(markcatdynhist.size() != 0) {
      LOG("MARKED RUNTIME GENERATED CODE:\n");
      for ( int cats = XED_CATEGORY_INVALID; cats != XED_CATEGORY_LAST; cats++ ) {
         LOG( "   " + CATEGORY_StringShort(cats) + ": "+ decstr(markcatdynhist[cats]) +"\n");
         totalmarkdynamicins += markcatdynhist[cats];
      }
      LOG("   TOTAL MAKRED DYNAMIC COUNT: "+decstr(totalmarkdynamicins)+"\n\n");
   }else {
       LOG("NO MARKED DYNAMIC CODE EXECUTED\n\n");
   }

   LOG("TOTAL INSTRUCTION COUNT: " + decstr(totalinsns+totalmarkinsns+totaldynamicins+totalmarkdynamicins)+"\n");
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "trace.out", "specify output file name");

KNOB<string> KnobInsMode(KNOB_MODE_WRITEONCE, "pintool",
    "m", "trace", "trace or only measure");

KNOB<string> KnobInsAddAddr(KNOB_MODE_WRITEONCE, "pintool",
    "a", "no", "add instruction address");

KNOB<string> KnobTrcModLoad(KNOB_MODE_WRITEONCE, "pintool",
    "l", "no", "trace module loading");

KNOB<string> KnobFilterFile(KNOB_MODE_WRITEONCE, "pintool",
    "f", "modulefilter.txt", "filter file");


INT32 Usage()
{
    PIN_ERROR("This PinTool optionally creates a disassembled trace of the program execution and also creates a histogram of executed extructions per XED categories\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();

    if(KnobInsMode.Value() == "measure") {
        mode = OpMode::measure;
        tracefile = NULL;
    }else {
		mode = OpMode::trace;
        LOG("Opening trace file\n");
        tracefile = fopen(KnobOutputFile.Value().c_str(), "wb");
    }

    if(KnobTrcModLoad.Value() == "yes") {
        modfile = fopen("moduletrace.txt","w");
        IMG_AddInstrumentFunction(ImageLoad, 0);
    }
	
    std::ifstream mf_file(KnobFilterFile.Value().c_str());
    if (mf_file.good()) {
        LOG("Using module filter file "+KnobFilterFile.Value()+"\n");
        std::string line;
        while (std::getline(mf_file, line))
        {
            if(line[0]=='-') {
                LOG("Filtering module "+line.substr(1)+"\n");
                modulefilter.insert(line.substr(1));
            }
        }
    }

    if(KnobInsAddAddr.Value() == "yes") {
        add_addr = true;
    }
	TRACE_AddInstrumentFunction(Trace, 0);
 
    PIN_AddFiniFunction(Fini, 0);
	LOG("Starting program...\n");
    PIN_StartProgram();
    
    return 0;
}
