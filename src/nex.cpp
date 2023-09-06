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
    dump,
    EQ,
    GT,
    LT,
    GE,
    LE,
    NE,
    AND,
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
};

enum class OpType {
    push,
    push_addr,
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

struct Program {
    std::vector<Op> ops;
    std::vector<const char*> strings;
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
            } else if (intrinsic == Intrinsic::GE) {
                out << "    mov rcx, 0\n";
                out << "    mov rdx, 1\n";
                out << "    pop rbx\n";
                out << "    pop rax\n";
                out << "    cmp rax, rbx\n";
                out << "    cmovge rcx, rdx\n";
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
};

struct ParseContext {
    std::unordered_map<std::string, int> constants;
    std::unordered_map<std::string, int> allocations;
    std::unordered_map<std::string, int> functions;

    std::optional<int> currentFunction;
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
                Error(token.loc, "unexpected identifier");
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

    if (context.allocations.find(name) != context.allocations.end()) {
        Error(loc, "redefinition of allocation '%s'", name.c_str());
        exit(-1);
    }

    if (context.allocations.find(name) != context.allocations.end()) {
        Error(loc, "redefinition of function '%s'", name.c_str());
        exit(-1);
    }
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
            } else if (context.allocations.find(token.string) != context.allocations.end()) {
                Op op(OpType::push_addr, token.loc, context.allocations[token.string]);

                program.ops.push_back(op);
            } else if (context.functions.find(token.string) != context.functions.end()) {
                Op op(OpType::call, token.loc, context.functions[token.string]);

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
                } else if (program.ops[blockip].type == OpType::skip_fun) {
                    Op op(OpType::ret, token.loc);

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

                context.allocations.insert({ allocName, program.memory });
                program.memory += val;
            } else if (token.keyword == Keyword::FUN) {
                if (context.currentFunction.has_value()) {
                    Error(token.loc, "a function definition is not allowed here");
                    exit(-1);
                }

                stack.push_back(program.ops.size());
                context.currentFunction = { program.ops.size() };
                
                Op skipOp(OpType::skip_fun, token.loc);
                program.ops.push_back(skipOp);

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

                context.functions.insert({ funName, context.currentFunction.value()+1 });
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