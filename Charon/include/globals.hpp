#pragma once
#include <string>

const std::string robloxVersion = "version-3c1b78b767674c66";
using Stk_t = void**;

#define SCF_WRAP_START _Pragma("optimize(\"\", off)")
#define SCF_WRAP_END _Pragma("optimize(\"\", on)")

#define SCF_END goto __scf_skip_end;__debugbreak();__halt();__scf_skip_end:{};
constexpr ULONG SCF_END_MARKER = 0xF4CC02EB; //^^ the above instructions translate to this
constexpr ULONGLONG SCF_STACK_PLACEHOLDER = 0x1493028DEAD;

#define SCF_STACK *const_cast<Stk_t*>(&__scf_ptr_stk);
#define SCF_START const Stk_t __scf_ptr_stk = reinterpret_cast<const Stk_t>(SCF_STACK_PLACEHOLDER); Stk_t Stack = SCF_STACK;
