#include <iostream>
#include <vector>
#include <unordered_map>
#include <string>
#include <sstream>
#include <iomanip>
#include <bitset>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>

#define PHYS_ADDR 0x1000 // Example physical address
#define MAP_SIZE 4096UL  // Map size (4KB)
#define MAP_MASK (MAP_SIZE - 1)

const int START_ADDRESS = 0x100;
const int MEMORY_SIZE = 1024;

std::vector<std::string> memory(MEMORY_SIZE, "");
std::unordered_map<std::string, int> symbol_table;
std::vector<std::string> label_order;

std::vector<std::string> tokenize(const std::string& line) {
    std::istringstream iss(line);
    std::vector<std::string> tokens;
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

void first_pass(const std::vector<std::string>& program) {
    int LC = START_ADDRESS;
    for (const auto& line : program) {
        auto tokens = tokenize(line);
        if (tokens.empty()) continue;

        if (tokens[0] == "ORG") {
            LC = std::stoi(tokens[1], nullptr, 16);
        }
        else if (line.find(':') != std::string::npos) {
            std::string label = tokens[0].substr(0, tokens[0].size() - 1);
            if (symbol_table.find(label) == symbol_table.end()) {
                symbol_table[label] = LC;
                label_order.push_back(label);
            }
            if (tokens[1] == "DEC" || tokens[1] == "HEX") {
                LC += 1;
            }
        }
        else if (tokens[0] != "END") {
            LC += 1;
        }
    }
}

void second_pass(const std::vector<std::string>& program, const std::unordered_map<std::string, std::string>& opcode_table) {
    int LC = START_ADDRESS;
    for (const auto& line : program) {
        auto tokens = tokenize(line);
        if (tokens.empty()) continue;

        if (tokens[0] == "ORG") {
            LC = std::stoi(tokens[1], nullptr, 16);
        }
        else if (tokens[0] == "END") {
            break;
        }
        else if (line.find(':') != std::string::npos) {
            if (tokens[1] == "DEC" || tokens[1] == "HEX") {
                int value = (tokens[1] == "DEC") ? std::stoi(tokens[2]) : std::stoi(tokens[2], nullptr, 16);
                memory[LC] = std::bitset<16>(value).to_string();
                LC += 1;
            }
        }
        else if (opcode_table.find(tokens[0]) != opcode_table.end()) {
            std::string opcode = opcode_table.at(tokens[0]);
            if (tokens.size() > 1 && symbol_table.find(tokens[1]) != symbol_table.end()) {
                int address = symbol_table[tokens[1]];
                std::string binary_address = std::bitset<12>(address).to_string();
                memory[LC] = opcode + binary_address;
                LC += 1;
            }
            else {
                memory[LC] = opcode + "000000000000";
                LC += 1;
            }
        }
        else if (tokens[0] == "CMA" || tokens[0] == "INC" || tokens[0] == "HLT") {
            std::string opcode = opcode_table.at(tokens[0]);
            memory[LC] = opcode + "000000000000";
            LC += 1;
        }
    }
}

void access_physical_memory(off_t target) {
    int fd;
    void* map_base, * virt_addr;
    unsigned long read_result, writeval;

    // Open /dev/mem
    if ((fd = open("/dev/mem", O_RDWR | O_SYNC)) == -1) {
        std::cerr << "Error opening /dev/mem" << std::endl;
        return;
    }

    // Map the physical memory to virtual memory
    map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);
    if (map_base == (void*)-1) {
        std::cerr << "Error mapping memory" << std::endl;
        close(fd);
        return;
    }

    // Calculate the virtual address
    virt_addr = (char*)map_base + (target & MAP_MASK);

    // Read the value at the target address
    read_result = *((unsigned long*)virt_addr);
    std::cout << "Value at address 0x" << std::hex << target << ": 0x" << read_result << std::endl;

    // Write a new value to the target address
    writeval = 0xDEADBEEF;
    *((unsigned long*)virt_addr) = writeval;
    std::cout << "Written value 0x" << std::hex << writeval << " to address 0x" << target << std::endl;

    // Clean up
    if (munmap(map_base, MAP_SIZE) == -1) {
        std::cerr << "Error unmapping memory" << std::endl;
    }
    close(fd);
}

int main() {
    std::vector<std::string> program = {
        "ORG 100",
        "LDA SUB",
        "CMA",
        "INC",
        "ADD MIN",
        "STA DIF",
        "HLT",
        "MIN: DEC 83",
        "SUB: DEC -23",
        "DIF: HEX 0",
        "END"
    };

    std::unordered_map<std::string, std::string> opcode_table = {
        {"LDA", "0001"},
        {"ADD", "0010"},
        {"STA", "0011"},
        {"CMA", "0111"},
        {"INC", "1000"},
        {"HLT", "1111"}
    };

    first_pass(program);
    second_pass(program, opcode_table);

    std::cout << "Symbol Table:\n";
    for (const auto& label : label_order) {
        std::cout << label << ": " << std::hex << symbol_table[label] << "\n";
    }

    std::cout << "\nMachine Code:\n";
    for (int address = START_ADDRESS; address < START_ADDRESS + program.size(); ++address) {
        if (!memory[address].empty()) {
            std::string binary_code = memory[address];
            std::cout << std::hex << address << ": " << binary_code << "\n";
        }
    }

    // Accessing physical memory
    off_t target = PHYS_ADDR; // Set the target physical address
    access_physical_memory(target);

    return 0;
}