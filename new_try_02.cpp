#define _CRT_SECURE_NO_WARNINGS

#define WINDOWS
#define X86_32

#ifdef X86_32
#define A_X32
#else
#define A_X64
#endif
//DR:
#include "dr_api.h"
#include "dr_tools.h"
#include "drmgr.h"
#include "drreg.h"

//c:
//#include <stdbool.h>

//cpp:
#include <vector>
#include <map>


struct module_info//TODO:OUT FROM THIS FILE   | TODO:C++
{
    uint id; //module_info valid only if (id != 0)
    app_pc start;
    app_pc end;
    module_data_t *m_data;//only for dr_module_contain_addr, as may not be contiguous
};

static file_t trace_file;
static file_t module_info_file;
static std::vector<module_info> modules;//MAYBE:<module_info *>   |   now, while we have only 3 fields ptr is needless  
                                        //MAYBE: Dictionary<app_pc start, module_info> and find addr between two keys: (key_1 <= pc < key_2) & (pc<=m[key_1].end) => pc in module

static bool with_reg = true;

inline bool check_ptr_in_module(app_pc ptr, size_t index)
{
    return modules[index].start <= ptr && ptr < modules[index].end && dr_module_contains_addr(modules[index].m_data, ptr);
}

size_t get_module_id(app_pc ptr)
{
    size_t len = modules.size();
    for (size_t i = 0; i < len; i++) {
        if (check_ptr_in_module(ptr, i)) return i;
    }
    return 0;
}

dr_emit_flags_t 
insertion_func(void *drcontext, void *tag, instrlist_t *instrlist, instr_t *inst, bool for_trace, bool translating, void *user_data)//for every instruction
{
    static void *prev_tag = NULL;
    static size_t offset = 0;
    if (prev_tag != tag) {
        static uint prev_module_id = 0;
        offset = 0;
        thread_id_t thr_id = dr_get_thread_id(drcontext);
        
        //or: dr_lookup_module?
        if (!(prev_module_id && check_ptr_in_module((app_pc)tag, prev_module_id))) {
            prev_module_id = get_module_id((app_pc)tag);
        }
        if(!prev_module_id) dr_fprintf(trace_file, "[%0p] [thread id = %u] [code is outside modules]:\n", tag, thr_id);
        else dr_fprintf(trace_file, "[%0p] [thread id = %u] [module id = %d]:\n", tag, thr_id, prev_module_id);

        prev_tag = tag;
    }
    #define tab "    "
    const char *spaces = "               ";
    int add_spaces = 8;
    { size_t ofs = offset / 10; while (ofs) { add_spaces--; ofs /= 10; } if (add_spaces < 1)add_spaces = 1; }
    int opcode = instr_get_opcode(inst);
    if (!instr_is_encoding_possible(inst)) {
        dr_fprintf(trace_file, tab "+%d%.*sNOT ENCODABLE: %02X", offset, add_spaces, spaces, opcode);
        add_spaces = 10;
        //goto insertion_func_AFTER_OUT;
    }
    else {
        const char *s_opcode = decode_opcode_name(opcode);
        dr_fprintf(trace_file, tab "+%d%.*s%02X(%s)", offset, add_spaces, spaces, opcode, s_opcode);
        add_spaces = 10;
        while (s_opcode[0]) { s_opcode++; add_spaces--; }
        add_spaces--;
        if (add_spaces < 1)add_spaces = 1;

    }
    
    dr_mcontext_t context = {sizeof(context), DR_MC_ALL};
    if (dr_get_mcontext(dr_get_current_drcontext(), &context)) {
        #ifdef X86_32
        dr_fprintf(trace_file, "%.*sREGs: " "eax = 0x%X" tab "ebx = 0x%X"  tab "ecx = 0x%X" tab "edx = 0x%X" tab "eip = 0x%X",
                    add_spaces, spaces, context.eax, context.ebx, context.ecx, context.edx, context.eip);
        #else
        TODO
        #endif
    }

    #undef tab
    insertion_func_AFTER_OUT:
    dr_fprintf(trace_file, "\n");
    offset += instr_length(drcontext, inst);
    return DR_EMIT_DEFAULT;
}

void 
module_load_func(void *drcontext, const module_data_t *info, bool loaded)
{
    static uint module_id = 0;
    module_id++;
   
    modules.push_back({module_id, info->start, info->end, dr_copy_module_data(info)});

    dr_fprintf(module_info_file, "[id = %04d]:[name = \"%s\"     path = \"%s\"]\n", module_id, dr_module_preferred_name(info), info->full_path);
}

void
module_unload_func(void *drcontext, const module_data_t *info)
{
    dr_fprintf(STDERR, "unload module: dr_context = %p\n", drcontext);//TODO:DEL

    size_t len = modules.size();
    for (size_t i = 0; i < len; i++) {
        auto& mi = modules[i];
        if (mi.id) {
            if (info->start == mi.start) {
                mi.id = 0;
                dr_free_module_data(mi.m_data);
                break;
            }
        }
    }
}


//void event_thread_init(void *drcontext){}
//void event_thread_exit(void *drcontext){}

void event_exit(void)
{
    dr_close_file(module_info_file);
    dr_close_file(trace_file);

    bool all_unreg = true;
    all_unreg &= drmgr_unregister_bb_insertion_event(insertion_func);
    all_unreg &= drmgr_unregister_module_load_event(module_load_func);
    all_unreg &= drmgr_unregister_module_unload_event(module_unload_func);
    if (!all_unreg) {
        dr_fprintf(STDERR, "not all event handlers were unregistered\n");
        //DR_ASSERT(false);
    }

    drmgr_exit();
}

void some_prog_init()
{
    modules.push_back({0});//for modules[_id].id == _id;
}

DR_EXPORT
void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_enable_console_printing();//MAYBE:DEL
    if (!drmgr_init()) { DR_ASSERT(false); }

    module_info_file = dr_open_file("module_info.txt", DR_FILE_WRITE_OVERWRITE);//TODO:MAKE:NOT_CONST
    trace_file = dr_open_file("#.TR#CE", DR_FILE_WRITE_OVERWRITE);//TODO:MAKE:NOT_CONST

    if (!module_info_file || !trace_file) {
        dr_fprintf(STDERR, "not all files were opened\n");
        DR_ASSERT(false);
    }

    dr_register_exit_event(event_exit);

    //for syscall analysis: (l guess)
    //drmgr_register_pre_syscall_event
    //drmgr_register_post_syscall_event

    //instr2instr_file = dr_open_file("I2I.TR#CE", DR_FILE_WRITE_OVERWRITE);
    //dr_register_trace_event(instru2instru_event);
    //drmgr_register_bb_instru2instru_event(instru2instru_event, NULL);

    if (//!drmgr_register_thread_init_event(event_thread_init) ||
        //!drmgr_register_thread_exit_event(event_thread_exit) ||
        !drmgr_register_bb_instrumentation_event(NULL, insertion_func, NULL) ||
        !drmgr_register_module_load_event(module_load_func) || 
        !drmgr_register_module_unload_event(module_unload_func)) {
        dr_fprintf(STDERR, "not all event handlers were created\n");
        DR_ASSERT(false);
    }
}
