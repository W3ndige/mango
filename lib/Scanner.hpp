#include "CLI/CLI.hpp"
#include "Yara.hpp"

class Scanner {  
    public:
        Scanner();
        
        bool scan();
        
        int parseArguments(int, char *[]);

        ~Scanner();
    
    private:
        CLI::App app;

        bool verbose;
        bool dumpMatches;
        bool recursiveScan; 

        std::string sourcePath;
        std::string targetPath;

};
