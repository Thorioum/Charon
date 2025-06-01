#pragma once
#include <string>

#define END_MARKER goto __scf_skip_end;__debugbreak();__debugbreak();__scf_skip_end:{};
constexpr ULONG END_MARKER_SIG = 0x02EB04EB; //jmprel+4,jmprel+2 //^^ the above instructions translate to this
constexpr ULONGLONG STACK_PLACEHOLDER = 0x1493028DEAD;

#define SCF_STACK *const_cast<void***>(&__scf_ptr_stk);
#define DEFINE_STACK const void** __scf_ptr_stk = reinterpret_cast<const void**>(STACK_PLACEHOLDER); void** Stack = SCF_STACK;
