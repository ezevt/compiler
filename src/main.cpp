#include <iostream>
#include <vector>
#include <sstream>
#include <fstream>
#include <unordered_map>
#include <algorithm>
#include <stdarg.h>
#include <string.h>

struct Loc {
    const char* file;
    int line;
    int col;
};

enum Intrinsic {
    plus,
    minus,
    dump
};

enum OpType {
    push,
    intrinsic
};

struct Op {
    OpType type;
    Loc loc;
    int value;
};

enum TokenType {
    word,
    integer,
    keyword // TODO: Implement
};

struct Token {
    TokenType type;
    Loc loc;
    union { int integer; const char* string; };
};

struct Program {
    std::vector<Op> ops;
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

    for (Op op : program.ops) {
        if (op.type == OpType::push) {
            out << "    push " << op.value << "\n";
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
            } else if (intrinsic == Intrinsic::dump) {
                out << "    pop rdi\n";
                out << "    call dump\n";
            }

        }
    }

    out << "    mov rax, 60\n";
    out << "    mov rdi, 0\n";
    out << "    syscall\n";

    return out.str();
}

std::unordered_map<std::string, Intrinsic> IntrinsicDictionary = {
    { "+", Intrinsic::plus },
    { "-", Intrinsic::minus },
    { "dump", Intrinsic::dump },
};

bool IsInteger(const std::string& s)
{
    std::string::const_iterator it = s.begin();
    while (it != s.end() && std::isdigit(*it)) ++it;
    return !s.empty() && it == s.end();
}

Program TokensToProgram(std::vector<Token>& tokens) {
    std::vector<Token> rtokens = std::move(tokens);
    std::reverse(rtokens.begin(), rtokens.end());
    Program program;

    while (rtokens.size() > 0) {
        Token token = rtokens.back();
        rtokens.pop_back();

        if (token.type == TokenType::word) {
            if (IntrinsicDictionary.find(token.string) != IntrinsicDictionary.end()) {
                Op op;
                op.loc = token.loc;
                op.type = OpType::intrinsic;
                op.value = IntrinsicDictionary[token.string];
                program.ops.push_back(op);
            } else {
                Error(token.loc, "unknown word '%s'", token.string);
                exit(-1);
            }
        }  else if (token.type == TokenType::integer) {
            Op op;
            op.loc = token.loc;
            op.type = OpType::push;
            op.value = token.integer;
            
            program.ops.push_back(op);
        }
    }

    return program;
}

std::vector<Token> Tokenize(const std::string& filepath) {
    std::stringstream file;
    {
        std::fstream input(filepath, std::ios::in);
        file << input.rdbuf();
    }


    std::vector<Token> tokens;
    std::string lineStr;
    int line = 1;

    while (std::getline(file, lineStr)) {

        std::stringstream lineStream(lineStr);

        std::string buf;

        for (int i = 0; i < lineStr.length(); i++) {
            if (!std::isspace(lineStr[i])) {
                int col = i+1;

                for (; i < lineStr.length(); i++) {
                    if (std::isspace(lineStr[i])) break;

                    buf.push_back(lineStr[i]);
                }

                if (IsInteger(buf)) {
                    Token newToken;
                    newToken.type = TokenType::integer;
                    newToken.loc = Loc { filepath.c_str(), line, col };
                    newToken.integer = std::stoi(buf);

                    tokens.push_back(newToken);
                } else {
                    Token newToken;
                    newToken.type = TokenType::word;
                    newToken.loc = Loc { filepath.c_str(), line, col };
                    newToken.string = strdup(buf.c_str());

                    tokens.push_back(newToken);
                }                

                buf.clear();
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