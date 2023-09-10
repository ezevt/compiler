#include <iostream>
#include <vector>
#include <sstream>
#include <fstream>
#include <unordered_map>
#include <algorithm>
#include <optional>
#include <stdarg.h>
#include <string.h>
#include <iomanip>
#include <tuple>
#include <assert.h>

const int RETURN_STACK_CAP_X86_64 = 4096;

struct Loc {
    const char* file;
    int line;
    int col;
};

enum class Intrinsic {
    plus,
    minus,
    mul,
    divmod,
    dump,
    EQ,
    GT,
    LT,
    GE,
    LE,
    NE,
    AND,
    OR,
    NOT,
    dup,
    over,
    swap,
    drop,
    rot,
    syscall1,
    syscall2,
    syscall3,
    syscall4,
    syscall5,
    syscall6,
    read8,
    store8,
    read16,
    store16,
    read32,
    store32,
    read64,
    store64,
    cast_int,
    cast_bool,
    cast_ptr,
    argc,
    argv
};

enum class Keyword {
    IF,
    ELSE,
    WHILE,
    DO,
    END,
    CONST,
    ALLOC,
    FUN,
    INCLUDE,
    ARROW,
    BIKESHEDDER
};

enum class OpType {
    push,
    push_addr,
    push_local_addr,
    push_string,
    intrinsic,
    IF,
    ELSE,
    WHILE,
    DO,
    END,
    skip_fun,
    fun,
    ret,
    call,
};

struct Op {
    OpType type;
    Loc loc;
    int value;

    Op();
    Op(OpType _type, Loc _loc, int _value = 0) : type(_type), loc(_loc), value(_value) {}
};

enum class TokenType {
    word,
    integer,
    keyword,
    string,
};

struct Token {
    TokenType type;
    Loc loc;
    union { int integer; const char* string; Keyword keyword; };

    Token() = default;
    Token(TokenType _type, Loc _loc) : type(_type), loc(_loc) {}
    Token(TokenType _type, Loc _loc, int _integer) : type(_type), loc(_loc), integer(_integer) {}
    Token(TokenType _type, Loc _loc, const char* _string) : type(_type), loc(_loc), string(_string) {}
    Token(TokenType _type, Loc _loc, Keyword _keyword) : type(_type), loc(_loc), keyword(_keyword) {}
};

enum class DataType {
    INT,
    PTR,
    BOOL
};

struct Contract {
    std::vector<DataType> ins;
    std::vector<DataType> outs;
};

struct Program {
    std::vector<Op> ops;
    std::vector<const char*> strings;
    std::unordered_map<int, Contract> contracts;
    int memory = 0;
};

void Error(const Loc& loc, const char* format, ...) {
    va_list args;
    va_start(args, format);

    std::cerr << loc.file << ":" << loc.line << ":" << loc.col << ": ERROR: ";
    
    char buffer[256]; // Adjust the buffer size as needed
    vsnprintf(buffer, sizeof(buffer), format, args);
    std::cerr << buffer;
    
    va_end(args);

    std::cerr << std::endl;
}

std::string Generate_linux_x86_64(Program& program) {
    std::stringstream out;

    out << "segment .text\n";
    out << "dump:\n";
    out << "    mov     r9, -3689348814741910323\n";
    out << "    sub     rsp, 40\n";
    out << "    mov     BYTE [rsp+31], 10\n";
    out << "    lea     rcx, [rsp+30]\n";
    out << ".L2:\n";
    out << "    mov     rax, rdi\n";
    out << "    lea     r8, [rsp+32]\n";
    out << "    mul     r9\n";
    out << "    mov     rax, rdi\n";
    out << "    sub     r8, rcx\n";
    out << "    shr     rdx, 3\n";
    out << "    lea     rsi, [rdx+rdx*4]\n";
    out << "    add     rsi, rsi\n";
    out << "    sub     rax, rsi\n";
    out << "    add     eax, 48\n";
    out << "    mov     BYTE [rcx], al\n";
    out << "    mov     rax, rdi\n";
    out << "    mov     rdi, rdx\n";
    out << "    mov     rdx, rcx\n";
    out << "    sub     rcx, 1\n";
    out << "    cmp     rax, 9\n";
    out << "    ja      .L2\n";
    out << "    lea     rax, [rsp+32]\n";
    out << "    mov     edi, 1\n";
    out << "    sub     rdx, rax\n";
    out << "    xor     eax, eax\n";
    out << "    lea     rsi, [rsp+32+rdx]\n";
    out << "    mov     rdx, r8\n";
    out << "    mov     rax, 1\n";
    out << "    syscall\n";
    out << "    add     rsp, 40\n";
    out << "    ret\n";
    out << "global _start\n";
    out << "_start:\n";
    out << "    mov [args_ptr], rsp\n";
    out << "    mov rax, ret_stack_end\n";
    out << "    mov [ret_stack_rsp], rax\n";
    for (int i = 0; i < program.ops.size(); i++) {
        Op op = program.ops[i];
        out << "addr_" << i << ":\n";
        if (op.type == OpType::push) {
            out << "    push " << op.value << "\n";
        } else if (op.type == OpType::push_string) {
            out << "    push str_" << op.value << "\n";
        } else if (op.type == OpType::push_addr) {
            out << "    mov rax, mem\n";
            out << "    add rax, " << op.value << "\n";
            out << "    push rax\n";
        } else if (op.type == OpType::push_local_addr) {
            out << "    mov rax, [ret_stack_rsp]\n";
            out << "    add rax, " << op.value << "\n";
            out << "    push rax\n";
            } else if (op.type == OpType::IF) {
            out << "    pop rax\n";
            out << "    test rax, rax\n";
            out << "    jz addr_" << op.value << "\n";
        } else if (op.type == OpType::ELSE) {
            out << "    jmp addr_" << op.value << "\n";
        } else if (op.type == OpType::WHILE) {
            out << "    ;; while\n";
        } else if (op.type == OpType::DO) {
            out << "    pop rax\n";
            out << "    test rax, rax\n";
            out << "    jz addr_" << op.value << "\n";
        } else if (op.type == OpType::END) {
            if (i+1 != op.value)
                out << "    jmp addr_" << op.value << "\n";
        } else if (op.type == OpType::skip_fun) {
            out << "    jmp addr_" << op.value << "\n";
        } else if (op.type == OpType::fun) {
            out << "    sub rsp, " << op.value << "\n";
            out << "    mov [ret_stack_rsp], rsp\n";
            out << "    mov rsp, rax\n";
        } else if (op.type == OpType::call) {
            out << "    mov rax, rsp\n";
            out << "    mov rsp, [ret_stack_rsp]\n";
            out << "    call addr_" << op.value << "\n";
            out << "    mov [ret_stack_rsp], rsp\n";
            out << "    mov rsp, rax\n";
        } else if (op.type == OpType::ret) {
            out << "    mov rax, rsp\n";
            out << "    mov rsp, [ret_stack_rsp]\n";
            out << "    add rsp, " << op.value << "\n";
            out << "    ret\n";
        } else if (op.type == OpType::intrinsic) {
            Intrinsic intrinsic = (Intrinsic)op.value;

            if (intrinsic == Intrinsic::plus) {
                out << "    pop rax\n";
                out << "    pop rbx\n";
                out << "    add rax, rbx\n";
                out << "    push rax\n";
            } else if (intrinsic == Intrinsic::minus) {
                out << "    pop rax\n";
                out << "    pop rbx\n";
                out << "    sub rbx, rax\n";
                out << "    push rbx\n";
            } else if (intrinsic == Intrinsic::mul) {
                out << "    pop rax\n";
                out << "    pop rbx\n";
                out << "    mul rbx\n";
                out << "    push rax\n";
            } else if (intrinsic == Intrinsic::divmod) {
                out << "    xor rdx, rdx\n";
                out << "    pop rbx\n";
                out << "    pop rax\n";
                out << "    div rbx\n";
                out << "    push rax\n";
                out << "    push rdx\n";
            } else if (intrinsic == Intrinsic::dump) {
                out << "    pop rdi\n";
                out << "    call dump\n";
            } else if (intrinsic == Intrinsic::EQ) {
                out << "    mov rcx, 0\n";
                out << "    mov rdx, 1\n";
                out << "    pop rax\n";
                out << "    pop rbx\n";
                out << "    cmp rax, rbx\n";
                out << "    cmove rcx, rdx\n";
                out << "    push rcx\n";
            } else if (intrinsic == Intrinsic::GT) {
                out << "    mov rcx, 0\n";
                out << "    mov rdx, 1\n";
                out << "    pop rbx\n";
                out << "    pop rax\n";
                out << "    cmp rax, rbx\n";
                out << "    cmovg rcx, rdx\n";
                out << "    push rcx\n";
            } else if (intrinsic == Intrinsic::LT) {
                out << "    mov rcx, 0\n";
                out << "    mov rdx, 1\n";
                out << "    pop rbx\n";
                out << "    pop rax\n";
                out << "    cmp rax, rbx\n";
                out << "    cmovl rcx, rdx\n";
                out << "    push rcx\n";
            } else if (intrinsic == Intrinsic::GE) {
                out << "    mov rcx, 0\n";
                out << "    mov rdx, 1\n";
                out << "    pop rbx\n";
                out << "    pop rax\n";
                out << "    cmp rax, rbx\n";
                out << "    cmovge rcx, rdx\n";
                out << "    push rcx\n";
            } else if (intrinsic == Intrinsic::LE) {
                out << "    mov rcx, 0\n";
                out << "    mov rdx, 1\n";
                out << "    pop rbx\n";
                out << "    pop rax\n";
                out << "    cmp rax, rbx\n";
                out << "    cmovle rcx, rdx\n";
                out << "    push rcx\n";
            } else if (intrinsic == Intrinsic::NE) {
                out << "    mov rcx, 0\n";
                out << "    mov rdx, 1\n";
                out << "    pop rbx\n";
                out << "    pop rax\n";
                out << "    cmp rax, rbx\n";
                out << "    cmovne rcx, rdx\n";
                out << "    push rcx\n";
            } else if (intrinsic == Intrinsic::AND) {
                out << "    pop rbx\n";
                out << "    pop rax\n";
                out << "    and rbx, rax\n";
                out << "    push rbx\n";
            } else if (intrinsic == Intrinsic::OR) {
                out << "    pop rbx\n";
                out << "    pop rax\n";
                out << "    or rbx, rax\n";
                out << "    push rbx\n";
            } else if (intrinsic == Intrinsic::NOT) {
                out << "    pop rbx\n";
                out << "    not rbx\n";
                out << "    push rbx\n";
            } else if (intrinsic == Intrinsic::dup) {
                out << "    pop rax\n";
                out << "    push rax\n";
                out << "    push rax\n";
            } else if (intrinsic == Intrinsic::over) {
                out << "    pop rax\n";
                out << "    pop rbx\n";
                out << "    push rbx\n";
                out << "    push rax\n";
                out << "    push rbx\n";
            } else if (intrinsic == Intrinsic::swap) {
                out << "    pop rax\n";
                out << "    pop rbx\n";
                out << "    push rax\n";
                out << "    push rbx\n";
            } else if (intrinsic == Intrinsic::drop) {
                out << "    pop rax\n";
            } else if (intrinsic == Intrinsic::rot) {
                out << "    pop rax\n";
                out << "    pop rbx\n";
                out << "    pop rcx\n";
                out << "    push rbx\n";
                out << "    push rax\n";
                out << "    push rcx\n";
            } else if (intrinsic == Intrinsic::syscall1) {
                out << "    pop rax\n";
                out << "    pop rdi\n";
                out << "    syscall\n";
                out << "    push rax\n";
            } else if (intrinsic == Intrinsic::syscall2) {
                out << "    pop rax\n";
                out << "    pop rdi\n";
                out << "    pop rsi\n";
                out << "    syscall\n";
                out << "    push rax\n";
            } else if (intrinsic == Intrinsic::syscall3) {
                out << "    pop rax\n";
                out << "    pop rdi\n";
                out << "    pop rsi\n";
                out << "    pop rdx\n";
                out << "    syscall\n";
                out << "    push rax\n";
            } else if (intrinsic == Intrinsic::syscall4) {
                out << "    pop rax\n";
                out << "    pop rdi\n";
                out << "    pop rsi\n";
                out << "    pop rdx\n";
                out << "    pop r10\n";
                out << "    syscall\n";
                out << "    push rax\n";
            } else if (intrinsic == Intrinsic::syscall5) {
                out << "    pop rax\n";
                out << "    pop rdi\n";
                out << "    pop rsi\n";
                out << "    pop rdx\n";
                out << "    pop r10\n";
                out << "    pop r8\n";
                out << "    syscall\n";
                out << "    push rax\n";
            } else if (intrinsic == Intrinsic::syscall6) {
                out << "    pop rax\n";
                out << "    pop rdi\n";
                out << "    pop rsi\n";
                out << "    pop rdx\n";
                out << "    pop r10\n";
                out << "    pop r8\n";
                out << "    pop r9\n";
                out << "    syscall\n";
                out << "    push rax\n";
            } else if (intrinsic == Intrinsic::read8) {
                out << "    pop rax\n";
                out << "    xor rbx, rbx\n";
                out << "    mov bl, [rax]\n";
                out << "    push rbx\n";
            } else if (intrinsic == Intrinsic::store8) {
                out << "    pop rax\n";
                out << "    pop rbx\n";
                out << "    mov [rax], bl\n";
            } else if (intrinsic == Intrinsic::read16) {
                out << "    pop rax\n";
                out << "    xor rbx, rbx\n";
                out << "    mov bx, [rax]\n";
                out << "    push rbx\n";
            } else if (intrinsic == Intrinsic::store16) {
                out << "    pop rax\n";
                out << "    pop rbx\n";
                out << "    mov [rax], bx\n";
            } else if (intrinsic == Intrinsic::read32) {
                out << "    pop rax\n";
                out << "    xor rbx, rbx\n";
                out << "    mov ebx, [rax]\n";
                out << "    push rbx\n";
            } else if (intrinsic == Intrinsic::store32) {
                out << "    pop rax\n";
                out << "    pop rbx\n";
                out << "    mov [rax], ebx\n";
            } else if (intrinsic == Intrinsic::read64) {
                out << "    pop rax\n";
                out << "    xor rbx, rbx\n";
                out << "    mov rbx, [rax]\n";
                out << "    push rbx\n";
            } else if (intrinsic == Intrinsic::store64) {
                out << "    pop rax\n";
                out << "    pop rbx\n";
                out << "    mov [rax], rbx\n";
            } else if (intrinsic == Intrinsic::cast_int) {
                // used for type checking
            } else if (intrinsic == Intrinsic::cast_bool) {
                // used for type checking
            } else if (intrinsic == Intrinsic::cast_ptr) {
                // used for type checking
            } else if (intrinsic == Intrinsic::argc) {
                out << "    mov rax, [args_ptr]\n";
                out << "    mov rax, [rax]\n";
                out << "    push rax\n";
            } else if (intrinsic == Intrinsic::argv) {
                out << "    mov rax, [args_ptr]\n";
                out << "    add rax, 8\n";
                out << "    push rax\n";
            }
        }
    }

    out << "addr_" << program.ops.size() << ":\n";
    out << "    mov rax, 60\n";
    out << "    mov rdi, 0\n";
    out << "    syscall\n";
    out << "segment .data\n";
    for (int i = 0; i < program.strings.size(); i++) {
        std::string s = program.strings[i];
        std::ostringstream oss;
        oss << "str_" << i << ": db ";

        std::vector<unsigned char> bytes(s.begin(), s.end());

        for (size_t i = 0; i < bytes.size(); ++i) {
            oss << "0x" << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]);
            if (i != bytes.size() - 1) {
                oss << ",";
            }
        }

        oss << ",0x0";

        oss << "\n";

        out << oss.str();
    }
    out << "segment .bss\n";
    out << "    args_ptr: resq 1\n";
    out << "    ret_stack_rsp: resq 1\n";
    out << "    ret_stack: resb " << RETURN_STACK_CAP_X86_64 << "\n";
    out << "    ret_stack_end: resq 1\n";
    out << "    mem: resb " << program.memory << "\n";

    return out.str();
}

std::unordered_map<std::string, Intrinsic> IntrinsicDictionary = {
    { "+", Intrinsic::plus },
    { "-", Intrinsic::minus },
    { "*", Intrinsic::mul },
    { "divmod", Intrinsic::divmod },
    { "dump", Intrinsic::dump },
    { "=", Intrinsic::EQ },
    { ">", Intrinsic::GT },
    { "<", Intrinsic::LT },
    { ">=", Intrinsic::GE },
    { "<=", Intrinsic::LE },
    { "!=", Intrinsic::NE },
    { "dup", Intrinsic::dup },
    { "over", Intrinsic::over },
    { "drop", Intrinsic::drop },
    { "swap", Intrinsic::swap },
    { "rot", Intrinsic::rot },
    { "and", Intrinsic::AND },
    { "or", Intrinsic::OR },
    { "not", Intrinsic::NOT },
    { "syscall1", Intrinsic::syscall1 },
    { "syscall2", Intrinsic::syscall2 },
    { "syscall3", Intrinsic::syscall3 },
    { "syscall4", Intrinsic::syscall4 },
    { "syscall5", Intrinsic::syscall5 },
    { "syscall6", Intrinsic::syscall6 },
    { "r8", Intrinsic::read8 },
    { "s8", Intrinsic::store8 },
    { "r16", Intrinsic::read16 },
    { "s16", Intrinsic::store16 },
    { "r32", Intrinsic::read32 },
    { "s32", Intrinsic::store32 },
    { "r64", Intrinsic::read64 },
    { "s64", Intrinsic::store64 },
    { "cast_int", Intrinsic::cast_int },
    { "cast_bool", Intrinsic::cast_bool },
    { "cast_ptr", Intrinsic::cast_ptr },
    { "argc", Intrinsic::argc },
    { "argv", Intrinsic::argv },
};

std::unordered_map<std::string, Keyword> KeywordDictionary = {
    { "if", Keyword::IF },
    { "else", Keyword::ELSE },
    { "while", Keyword::WHILE },
    { "do", Keyword::DO },
    { "end", Keyword::END },
    { "const", Keyword::CONST },
    { "alloc", Keyword::ALLOC },
    { "fun", Keyword::FUN },
    { "include", Keyword::INCLUDE },
    { "->", Keyword::ARROW },
    { "--", Keyword::BIKESHEDDER },
};

std::unordered_map<std::string, DataType> DataTypeDictionary = {
    { "int", DataType::INT },
    { "ptr", DataType::PTR },
    { "bool", DataType::BOOL },
};

struct Function {
    int op;
    std::unordered_map<std::string, int> localAllocations;
    int localMemory = 0;
};

struct ParseContext {
    std::unordered_map<std::string, int> constants;
    std::unordered_map<std::string, int> allocations;
    std::unordered_map<std::string, Function> functions;

    std::optional<Function*> currentFunction;
};

int EvalConstant(ParseContext& context, std::vector<Token>& rtokens) {
    std::vector<int> stack;
    Token token;

    while (rtokens.size() > 0) {
        token = rtokens.back();
        rtokens.pop_back();

        if (token.type == TokenType::keyword) {
            if (token.keyword == Keyword::END) {
                break;
            } else {
                Error(token.loc, "unexpected keyword");
                exit(-1);
            }
        } else if (token.type == TokenType::integer) {
            stack.push_back(token.integer);
        } else if (token.type == TokenType::word) {
            if (IntrinsicDictionary.find(token.string) != IntrinsicDictionary.end()) {
                Intrinsic intrinsic = IntrinsicDictionary[token.string];

                if (intrinsic == Intrinsic::plus) {
                    if (stack.size() < 2) {
                        Error(token.loc, "not enough arguments for the '%s' intrinsic", token.string);
                        exit(-1);
                    }

                    int a = stack.back();
                    stack.pop_back();
                    int b = stack.back();
                    stack.pop_back();

                    stack.push_back(a+b);
                } else if (intrinsic == Intrinsic::minus) {
                    if (stack.size() < 2) {
                        Error(token.loc, "not enough arguments for the '%s' intrinsic", token.string);
                        exit(-1);
                    }

                    int b = stack.back();
                    stack.pop_back();
                    int a = stack.back();
                    stack.pop_back();

                    stack.push_back(a-b);
                } else if (intrinsic == Intrinsic::mul) {
                    if (stack.size() < 2) {
                        Error(token.loc, "not enough arguments for the '%s' intrinsic", token.string);
                        exit(-1);
                    }

                    int a = stack.back();
                    stack.pop_back();
                    int b = stack.back();
                    stack.pop_back();

                    stack.push_back(a*b);
                } else if (intrinsic == Intrinsic::drop) {
                    if (stack.size() < 2) {
                        Error(token.loc, "not enough arguments for the '%s' intrinsic", token.string);
                        exit(-1);
                    }

                    stack.pop_back();
                }
            } else if (context.constants.find(token.string) != context.constants.end()) {
                stack.push_back(context.constants[token.string]);
            } else {
                Error(token.loc, "unknown word '%s'", token.string);
                exit(-1);
            }
        }
    }

    if (stack.size() != 1) {
        Error(token.loc, "compile-time evaluation must be a single number");
        exit(-1);
    }

    return stack.back();
}

void CheckNameRedefinition(const ParseContext& context, const std::string& name, const Loc& loc) {
    if (IntrinsicDictionary.find(name) != IntrinsicDictionary.end()) {
        Error(loc, "redefinition of intrinsic '%s'", name.c_str());
        exit(-1);
    }

    if (context.constants.find(name) != context.constants.end()) {
        Error(loc, "redefinition of constant '%s'", name.c_str());
        exit(-1);
    }

    if (context.functions.find(name) != context.functions.end()) {
        Error(loc, "redefinition of function '%s'", name.c_str());
        exit(-1);
    }

    if (context.currentFunction.has_value()) {
        if (context.currentFunction.value()->localAllocations.find(name) != context.currentFunction.value()->localAllocations.end()) {
            Error(loc, "redefinition of local allocation '%s'", name.c_str());
            exit(-1);
        }
    } else {
        if (context.allocations.find(name) != context.allocations.end()) {
            Error(loc, "redefinition of allocation '%s'", name.c_str());
            exit(-1);
        }
    }
}

std::tuple<std::vector<DataType>, Keyword> ParseContractList(std::vector<Token>& rtokens, std::vector<Keyword> stop) {
    std::vector<DataType> args;

    Token token;
    while (rtokens.size() > 0) {
        token = rtokens.back();
        rtokens.pop_back();

        if (token.type == TokenType::word) {
            if (DataTypeDictionary.find(token.string) != DataTypeDictionary.end()) {
                args.push_back(DataTypeDictionary[token.string]);
            } else {
                Error(token.loc, "unknown data type '%s'", token.string);
                exit(-1);
            }
        } else if (token.type == TokenType::keyword) {
            for (auto s : stop) {
                if (token.keyword == s) {
                    return { args, s };
                }
            }
            Error(token.loc, "unexpected keyword in function definition");
            exit(-1);
        } else {
            Error(token.loc, "unexpected token in function definition");
            exit(-1);
        }
    }

    Error(token.loc, "unexpected end of file");
    exit(-1);
}

Contract ParseContract(std::vector<Token>& rtokens) {
    Contract contract;

    auto in = ParseContractList(rtokens, { Keyword::BIKESHEDDER, Keyword::ARROW });
    contract.ins = std::get<0>(in);

    if (std::get<1>(in) == Keyword::ARROW) return contract;


    auto out = ParseContractList(rtokens, { Keyword::ARROW });
    contract.outs = std::get<0>(out);
    return contract;
}

std::vector<Token> Tokenize(const std::string& filepath);

Program TokensToProgram(std::vector<Token>& tokens) {

    std::vector<int> stack;
    std::vector<Token> rtokens = std::move(tokens);
    std::reverse(rtokens.begin(), rtokens.end());
    Program program;
    ParseContext context;
    
    while (rtokens.size() > 0) {
        Token token = rtokens.back();
        rtokens.pop_back();

        if (token.type == TokenType::word) {
            if (IntrinsicDictionary.find(token.string) != IntrinsicDictionary.end()) {
                Op op(OpType::intrinsic, token.loc, (int)IntrinsicDictionary[token.string]);

                program.ops.push_back(op);
            } else if (context.constants.find(token.string) != context.constants.end()) {
                Op op(OpType::push, token.loc, context.constants[token.string]);

                program.ops.push_back(op);
            } else if (context.currentFunction.has_value() && context.currentFunction.value()->localAllocations.find(token.string) != context.currentFunction.value()->localAllocations.end()) {
                Op op(OpType::push_local_addr, token.loc, context.currentFunction.value()->localAllocations[token.string]);

                program.ops.push_back(op);
            } else if (context.allocations.find(token.string) != context.allocations.end()) {
                Op op(OpType::push_addr, token.loc, context.allocations[token.string]);

                program.ops.push_back(op);
            } else if (context.functions.find(token.string) != context.functions.end()) {
                Op op(OpType::call, token.loc, context.functions[token.string].op);

                program.ops.push_back(op);
            } else {
                Error(token.loc, "unknown word '%s'", token.string);
                exit(-1);
            }
        }  else if (token.type == TokenType::integer) {
            Op op(OpType::push, token.loc, token.integer);

            program.ops.push_back(op);
        }  else if (token.type == TokenType::string) {
            Op op(OpType::push_string, token.loc, program.strings.size());
            
            program.strings.push_back(token.string);

            program.ops.push_back(op);
        } else if (token.type == TokenType::keyword) {
            if (token.keyword == Keyword::IF) {
                stack.push_back(program.ops.size());

                Op op(OpType::IF, token.loc);

                program.ops.push_back(op);
            } else if (token.keyword == Keyword::ELSE) {
                int ifip = stack.back();
                stack.pop_back();

                stack.push_back(program.ops.size());
                
                if (program.ops[ifip].type != OpType::IF) {
                    Error(program.ops[ifip].loc, "'else' can only be used in 'if' blocks");
                    exit(-1);
                }

                program.ops[ifip].value = program.ops.size() + 1;

                Op op(OpType::ELSE, token.loc);

                program.ops.push_back(op);
            } else if (token.keyword == Keyword::WHILE) {
                stack.push_back(program.ops.size());
                
                Op op(OpType::WHILE, token.loc);

                program.ops.push_back(op);
            } else if (token.keyword == Keyword::DO) {
                int whileip = stack.back();
                stack.pop_back();

                stack.push_back(program.ops.size());
                
                if (program.ops[whileip].type != OpType::WHILE) {
                    Error(program.ops[whileip].loc, "'do' can only be used in 'while' blocks");
                    exit(-1);
                }

                Op op(OpType::DO, token.loc, whileip);

                program.ops.push_back(op);
            } else if (token.keyword == Keyword::END) {
                int blockip = stack.back();
                stack.pop_back();

                if (program.ops[blockip].type == OpType::IF || program.ops[blockip].type == OpType::ELSE) {
                    program.ops[blockip].value = program.ops.size();

                    Op op(OpType::END, token.loc, program.ops.size() + 1);

                    program.ops.push_back(op);
                } else if (program.ops[blockip].type == OpType::DO) {
                    Op op(OpType::END, token.loc, program.ops[blockip].value);

                    program.ops[blockip].value = program.ops.size()+1;

                    program.ops.push_back(op);
                } else if (program.ops[blockip].type == OpType::fun) {
                    program.ops[blockip].value = context.currentFunction.value()->localMemory;

                    blockip = stack.back();
                    stack.pop_back();
                    
                    Op op(OpType::ret, token.loc, context.currentFunction.value()->localMemory);
                    program.ops[blockip].value = program.ops.size()+1;

                    program.ops.push_back(op);

                    context.currentFunction = {};
                } else {
                    Error(program.ops[blockip].loc, "'end' can only close 'if', 'else' or 'while-do' blocks");
                    exit(-1);
                }
                
            } else if (token.keyword == Keyword::CONST) {
                Token nameTok = rtokens.back();
                rtokens.pop_back();

                if (nameTok.type != TokenType::word) {
                    Error(token.loc, "expected name");
                    exit(-1);
                }

                const char* constName = nameTok.string;
                Loc constLoc = nameTok.loc;

                CheckNameRedefinition(context, constName, constLoc);

                int val = EvalConstant(context, rtokens);

                context.constants.insert({ constName, val });
            } else if (token.keyword == Keyword::ALLOC) {
                Token nameTok = rtokens.back();
                rtokens.pop_back();

                if (nameTok.type != TokenType::word) {
                    Error(token.loc, "expected name");
                    exit(-1);
                }

                const char* allocName = nameTok.string;
                Loc allocLoc = nameTok.loc;

                CheckNameRedefinition(context, allocName, allocLoc);

                int val = EvalConstant(context, rtokens);

                if (context.currentFunction.has_value()) {
                    context.currentFunction.value()->localAllocations.insert({ allocName, context.currentFunction.value()->localMemory });
                    context.currentFunction.value()->localMemory += val;
                } else {
                    context.allocations.insert({ allocName, program.memory });
                    program.memory += val;
                }
            } else if (token.keyword == Keyword::FUN) {
                if (context.currentFunction.has_value()) {
                    Error(token.loc, "a function definition is not allowed here");
                    exit(-1);
                }

                int funAddr = program.ops.size();
                
                stack.push_back(program.ops.size());
                Op skipOp(OpType::skip_fun, token.loc);
                program.ops.push_back(skipOp);

                stack.push_back(program.ops.size());
                Op funOp(OpType::fun, token.loc);
                program.ops.push_back(funOp);
                
                Token nameTok = rtokens.back();
                rtokens.pop_back();

                if (nameTok.type != TokenType::word) {
                    Error(token.loc, "expected name");
                    exit(-1);
                }

                const char* funName = nameTok.string;
                Loc funLoc = nameTok.loc;

                CheckNameRedefinition(context, funName, funLoc);

                Contract contract = ParseContract(rtokens);

                context.functions.insert({ funName, { funAddr+1 } });
                program.contracts[funAddr+1] = contract;

                context.currentFunction = &context.functions[funName];
            } else if (token.keyword == Keyword::INCLUDE) {
                Token pathTok = rtokens.back();
                rtokens.pop_back();

                if (pathTok.type != TokenType::string) {
                    Error(token.loc, "expected path");
                    exit(-1);
                }

                const char* includePath = pathTok.string;
                Loc includeLoc = pathTok.loc;

                std::vector<Token> includeTokens = Tokenize(includePath);
                std::reverse(includeTokens.begin(), includeTokens.end());
                rtokens.insert(rtokens.end(), includeTokens.begin(), includeTokens.end());
            }
        }
    }

    if (stack.size() != 0)
        Error(program.ops[stack.back()].loc, "unclosed block");

    return program;
}

void NotEnoughArguments(const Op& op) {
    if (op.type == OpType::intrinsic) {
        Error(op.loc, "not enough arguments for intrinsic");
    } else if (op.type == OpType::IF) {
        Error(op.loc, "not enough arguments for if-block condition");
    } else if (op.type == OpType::DO) {
        Error(op.loc, "not enough arguments for while-do condition");
    } else {
        Error(op.loc, "unreachable");
    }
}

typedef std::vector<DataType> DataStack;

void PrintDataStack(const DataStack& b) {
    for (int i = 0; i < b.size(); i++) {
        if (b[i] == DataType::INT) {
            std::cout << "INT, ";
        } else if (b[i] == DataType::PTR) {
            std::cout << "PTR, ";
        } else if (b[i] == DataType::BOOL) {
            std::cout << "BOOL, ";
        } else {
            std::cout << "UNKNOWN, ";
        }

    }
    std::cout << std::endl;
}

bool EqualStacks(const DataStack& a, const DataStack& b) {
    if (a.size() != b.size()) {
        return false;
    }

    for (size_t i = 0; i < a.size(); i++) {
        if ((int)a[i] != (int)b[i]) {
            return false;
        }
    }
    return true;
}

void TypeCheckContract(Op op, DataStack& stack, const Contract& contract) {
    std::vector<DataType> ins(contract.ins);

    while (stack.size() > 0 && ins.size() > 0) {
        DataType actual = stack.back();
        stack.pop_back();
        DataType expected = ins.back();
        ins.pop_back();

        if (actual != expected) {
            Error(op.loc, "unexpected data type");
            exit(-1);
        }
    }

    if (stack.size() < ins.size()) {
        Error(op.loc, "not enough arguments provided");
    }

    for (DataType type : contract.outs) {
        stack.push_back(type);
    }
}

void TypeCheckProgram(Program& program) {
    DataStack stack;
    std::vector<std::tuple<DataStack, OpType>> blockStack;
    DataStack functionReturn;

    for (int i = 0; i < program.ops.size(); i++) {
        Op op = program.ops[i];
        if (op.type == OpType::push) {
            stack.push_back(DataType::INT);
        } else if (op.type == OpType::push_string) {
            stack.push_back(DataType::PTR);
        } else if (op.type == OpType::push_addr) {
            stack.push_back(DataType::PTR);
        } else if (op.type == OpType::push_local_addr) {
            stack.push_back(DataType::PTR);
        } else if (op.type == OpType::IF) {
            if (stack.size() < 1) {
                NotEnoughArguments(op);
                exit(-1);
            }

            DataType a = stack.back();
            stack.pop_back();

            if (a != DataType::BOOL) {
                Error(op.loc, "invalid argument for if-block condition. Expected BOOL");
                exit(-1);
            }
            blockStack.push_back({ DataStack(stack), op.type });
        } else if (op.type == OpType::ELSE) {
            DataStack expectedStack = std::get<0>(blockStack.back());
            OpType blockType = std::get<1>(blockStack.back());
            blockStack.pop_back();

            blockStack.push_back({ DataStack(stack), op.type });
            stack = expectedStack;
        } else if (op.type == OpType::WHILE) {
            blockStack.push_back({ DataStack(stack), op.type });
        } else if (op.type == OpType::DO) {
            if (stack.size() < 1) {
                NotEnoughArguments(op);
                exit(-1);
            }

            DataType a = stack.back();
            stack.pop_back();

            if (a != DataType::BOOL) {
                Error(op.loc, "invalid argument for while-do condition. Expected BOOL");
                exit(-1);
            }

            DataStack expectedStack = std::get<0>(blockStack.back());
            OpType blockType = std::get<1>(blockStack.back());
            blockStack.pop_back();

            if (!EqualStacks(stack, expectedStack)) {
                Error(op.loc, "while-do condition cannot alter the types of the arguments in the stack");
                exit(-1);
            }

            blockStack.push_back({ DataStack(stack), op.type });
        } else if (op.type == OpType::END) {
            DataStack expectedStack = std::get<0>(blockStack.back());
            OpType blockType = std::get<1>(blockStack.back());
            blockStack.pop_back();

            if (blockType == OpType::IF) {
                if (!EqualStacks(stack, expectedStack)) {
                    Error(op.loc, "else-less if cannot alter the types of the arguments in the stack");
                    exit(-1);
                }
            } else if (blockType == OpType::ELSE) {
                if (!EqualStacks(stack, expectedStack)) {
                    Error(op.loc, "both branches of the if-block must result in the same types of the arguments in the stack");
                    exit(-1);
                }
            } else if (blockType == OpType::DO) {
                if (!EqualStacks(stack, expectedStack)) {
                    Error(op.loc, "while-do cannot alter the types of the arguments in the stack");
                    exit(-1);
                }
            }
        } else if (op.type == OpType::skip_fun) {

        } else if (op.type == OpType::fun) {
            blockStack.push_back({ DataStack(stack), op.type });

            stack = program.contracts[i].ins;
            functionReturn = program.contracts[i].outs;
        } else if (op.type == OpType::call) {
            TypeCheckContract(op, stack, program.contracts[op.value]);
        } else if (op.type == OpType::ret) {
            DataStack prevStack = std::get<0>(blockStack.back());
            OpType blockType = std::get<1>(blockStack.back());
            blockStack.pop_back();

            if (!EqualStacks(stack, functionReturn)) {
                Error(op.loc, "unexpected data in the stack");
                exit(-1);
            }

            stack = prevStack;
        } else if (op.type == OpType::intrinsic) {
            Intrinsic intrinsic = (Intrinsic)op.value;

            if (intrinsic == Intrinsic::plus) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                if (a == DataType::INT && b == DataType::INT) {
                    stack.push_back(DataType::INT);
                } else if (a == DataType::INT && b == DataType::PTR) {
                    stack.push_back(DataType::PTR);
                } else if (a == DataType::PTR && b == DataType::INT) {
                    stack.push_back(DataType::PTR);
                } else {
                    Error(op.loc, "invalid arguments for '+' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::minus) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                if (a == b && (a == DataType::INT || a == DataType::PTR)) {
                    stack.push_back(DataType::INT);
                } else if (b == DataType::PTR && a == DataType::INT) {
                    stack.push_back(DataType::PTR);
                } else {
                    Error(op.loc, "invalid arguments for '-' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::mul) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                if (a == b && a == DataType::INT) {
                    stack.push_back(DataType::INT);
                } else {
                    Error(op.loc, "invalid arguments for '*' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::divmod) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                if (a == b && a == DataType::INT) {
                    stack.push_back(DataType::INT);
                    stack.push_back(DataType::INT);
                } else {
                    Error(op.loc, "invalid arguments for 'divmod' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::dump) {
                if (stack.size() < 1) {
                    NotEnoughArguments(op);
                    exit(-1);
                }

                stack.pop_back();
            } else if (intrinsic == Intrinsic::EQ) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                if (a == b && a == DataType::INT) {
                    stack.push_back(DataType::BOOL);
                } else {
                    Error(op.loc, "invalid arguments for '=' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::GT) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                if (a == b && a == DataType::INT) {
                    stack.push_back(DataType::BOOL);
                } else {
                    Error(op.loc, "invalid arguments for '>' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::LT) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                if (a == b && a == DataType::INT) {
                    stack.push_back(DataType::BOOL);
                } else {
                    Error(op.loc, "invalid arguments for '<' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::GE) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                if (a == b && a == DataType::INT) {
                    stack.push_back(DataType::BOOL);
                } else {
                    Error(op.loc, "invalid arguments for '>=' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::LE) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                if (a == b && a == DataType::INT) {
                    stack.push_back(DataType::BOOL);
                } else {
                    Error(op.loc, "invalid arguments for '<=' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::NE) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                if (a == b && a == DataType::INT) {
                    stack.push_back(DataType::BOOL);
                } else {
                    Error(op.loc, "invalid arguments for '!=' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::AND) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                if (a == b && (a == DataType::BOOL || a == DataType::INT)) {
                    stack.push_back(a);
                } else {
                    Error(op.loc, "invalid arguments for 'and' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::OR) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                if (a == b && (a == DataType::BOOL || a == DataType::INT)) {
                    stack.push_back(a);
                } else {
                    Error(op.loc, "invalid arguments for 'or' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::NOT) {
                if (stack.size() < 1) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();

                if (a == DataType::BOOL || a == DataType::INT) {
                    stack.push_back(a);
                } else {
                    Error(op.loc, "invalid arguments for 'not' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::dup) {
                if (stack.size() < 1) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();

                stack.push_back(a);
                stack.push_back(a);
            } else if (intrinsic == Intrinsic::over) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                stack.push_back(b);
                stack.push_back(a);
                stack.push_back(b);
            } else if (intrinsic == Intrinsic::swap) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                stack.push_back(a);
                stack.push_back(b);
            } else if (intrinsic == Intrinsic::drop) {
                if (stack.size() < 1) {
                    NotEnoughArguments(op);
                    exit(-1);
                }

                stack.pop_back();
            } else if (intrinsic == Intrinsic::rot) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();
                DataType c = stack.back();
                stack.pop_back();
                
                stack.push_back(b);
                stack.push_back(a);
                stack.push_back(c);
            } else if (intrinsic == Intrinsic::syscall1) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }

                stack.pop_back();
                stack.pop_back();

                stack.push_back(DataType::INT);
            } else if (intrinsic == Intrinsic::syscall2) {
                if (stack.size() < 3) {
                    NotEnoughArguments(op);
                    exit(-1);
                }

                stack.pop_back();
                stack.pop_back();
                stack.pop_back();

                stack.push_back(DataType::INT);
            } else if (intrinsic == Intrinsic::syscall3) {
                if (stack.size() < 4) {
                    NotEnoughArguments(op);
                    exit(-1);
                }

                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                
                stack.push_back(DataType::INT);
            } else if (intrinsic == Intrinsic::syscall4) {
                if (stack.size() < 5) {
                    NotEnoughArguments(op);
                    exit(-1);
                }

                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                
                stack.push_back(DataType::INT);
            } else if (intrinsic == Intrinsic::syscall5) {
                if (stack.size() < 6) {
                    NotEnoughArguments(op);
                    exit(-1);
                }

                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                
                stack.push_back(DataType::INT);
            } else if (intrinsic == Intrinsic::syscall6) {
                if (stack.size() < 7) {
                    NotEnoughArguments(op);
                    exit(-1);
                }

                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                stack.pop_back();
                
                stack.push_back(DataType::INT);
            } else if (intrinsic == Intrinsic::read8) {
                if (stack.size() < 1) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();

                if (a == DataType::PTR) {
                    stack.push_back(DataType::INT);
                } else {
                    Error(op.loc, "invalid arguments for 'r8' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::store8) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                if (a != DataType::PTR) {
                    Error(op.loc, "invalid arguments for 's8' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::read16) {
                if (stack.size() < 1) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();

                if (a == DataType::PTR) {
                    stack.push_back(DataType::INT);
                } else {
                    Error(op.loc, "invalid arguments for 'r16' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::store16) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                if (a != DataType::PTR) {
                    Error(op.loc, "invalid arguments for 's16' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::read32) {
                if (stack.size() < 1) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();

                if (a == DataType::PTR) {
                    stack.push_back(DataType::INT);
                } else {
                    Error(op.loc, "invalid arguments for 'r32' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::store32) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                if (a != DataType::PTR) {
                    Error(op.loc, "invalid arguments for 's32' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::read64) {
                if (stack.size() < 1) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();

                if (a == DataType::PTR) {
                    stack.push_back(DataType::INT);
                } else {
                    Error(op.loc, "invalid arguments for 'r64' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::store64) {
                if (stack.size() < 2) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();
                DataType b = stack.back();
                stack.pop_back();

                if (a != DataType::PTR) {
                    Error(op.loc, "invalid arguments for 's64' intrinsic");
                    exit(-1);
                }
            } else if (intrinsic == Intrinsic::cast_int) {
                if (stack.size() < 1) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();

                stack.push_back(DataType::INT);
            } else if (intrinsic == Intrinsic::cast_bool) {
                if (stack.size() < 1) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();

                stack.push_back(DataType::BOOL);
            } else if (intrinsic == Intrinsic::cast_ptr) {
                if (stack.size() < 1) {
                    NotEnoughArguments(op);
                    exit(-1);
                }
                
                DataType a = stack.back();
                stack.pop_back();

                stack.push_back(DataType::PTR);
            } else if (intrinsic == Intrinsic::argc) {
                stack.push_back(DataType::INT);
            } else if (intrinsic == Intrinsic::argv) {
                stack.push_back(DataType::PTR);
            } else {
                Error(op.loc, "unreachable");
                exit(-1);
            }
        }
    }

    if (stack.size() != 0) {
        std::cerr << "ERROR: unhandled data on the stack" << std::endl;
        exit(-1);
    }
}

bool IsInteger(const std::string& s)
{
    std::string::const_iterator it = s.begin();
    while (it != s.end() && std::isdigit(*it)) ++it;
    return !s.empty() && it == s.end();
}

std::vector<Token> Tokenize(const std::string& filepath) {
    std::ifstream input(filepath);
    if (!input.is_open()) {
        std::cout << "could not open file '" << filepath << "'" << std::endl;
        exit(-1);
        return {};
    }

    std::vector<Token> tokens;
    std::string lineStr;
    int line = 1;

    const char* filepathd = strdup(filepath.c_str());

    while (std::getline(input, lineStr)) {

        std::stringstream lineStream(lineStr);

        std::string buf;

        for (int i = 0; i < lineStr.length(); i++) {
            if (!std::isspace(lineStr[i])) {
                buf.clear();
                int col = i+1;

                Loc loc = { filepathd, line, col };

                bool comment = false;

                if (lineStr[i] == '"') {
                    i++;
                    while (i < lineStr.length() && lineStr[i] != '"') {
                        if (lineStr[i] == '\\') {
                            i++;

                            if (i >= lineStr.length())
                                break;

                            if (lineStr[i] == 'n') {
                                buf.push_back('\n');
                            } else if (lineStr[i] == '"') {
                                buf.push_back('"');
                            }
                        } else {
                            buf.push_back(lineStr[i]);
                        }
                        i++;
                    }

                    if (lineStr[i] != '"') {
                        Error(loc, "unclosed string literal");
                        exit(-1);
                    }

                    Token newToken(TokenType::string, loc, strdup(buf.c_str()));
                    tokens.push_back(newToken);

                    i++;
                    buf.clear();

                    continue;
                }

                for (; i < lineStr.length(); i++) {
                    if (std::isspace(lineStr[i])) break;

                    if (lineStr[i] == '/') {
                        if (i+1 < lineStr.length() && lineStr[i+1] == '/') {
                            comment = true;
                        }  

                        break;
                    }

                    buf.push_back(lineStr[i]);
                }

                if (buf.length() == 0) break;

                if (IsInteger(buf)) {
                    Token newToken = Token(TokenType::integer, loc, std::stoi(buf));

                    tokens.push_back(newToken);
                } else if (KeywordDictionary.find(buf) != KeywordDictionary.end()) {
                    Token newToken = Token(TokenType::keyword, loc, KeywordDictionary[buf]);

                    tokens.push_back(newToken);
                } else {
                    Token newToken(TokenType::word, loc, strdup(buf.c_str()));

                    tokens.push_back(newToken);
                }                

                buf.clear();

                if (comment) break;
            }
        }

        line++;
    }

    return tokens;
}

void CmdEcho(const std::string& cmd) {
    std::cout << "[CMD] " << cmd << std::endl;
    system(cmd.c_str());
}

int main(int argc, char* argv[]) {
    
    if (argc < 2) {
        std::cerr << "ERROR: expected a file" << std::endl;
        return -1;
    }

    std::vector<Token> tokens = Tokenize(argv[1]);
    Program program = TokensToProgram(tokens);
    TypeCheckProgram(program);
    std::string asmCode = Generate_linux_x86_64(program);

    {
        std::ofstream outFile("out.asm");

        outFile << asmCode;

        outFile.close();
    }

    CmdEcho("nasm -felf64 out.asm");
    CmdEcho("ld -o out out.o");

    return 0;
}