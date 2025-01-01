#include <map>
#include <cstdint>
#include <sys/wait.h>
#include <filesystem>
#include <vector>

extern "C" {
    #define namespace ns
    #include <yara_x.h>
    #undef namespace
}


using PatternMatch  = std::tuple<int, int>;
using PatternMap    = std::map<const char *, std::vector<PatternMatch>>;
using RuleMap       = std::map<const char *, PatternMap>;
using FileMap       = std::map<std::filesystem::path, RuleMap>;
using FullMatchCb   = std::function<void(RuleMap, void *)>;


class Yara {  
    public:
        Yara(uint32_t);
        Yara(uint32_t, bool);

        bool addSource(const char *);
        bool addSourceFromFile(std::filesystem::path);
        bool initScanner();
        bool scanFile(std::filesystem::path);
        
        void cleanResults();
        void addOnFullMatchCallback(FullMatchCb);

        RuleMap getMatchedIdentifiersForFile(std::filesystem::path);

        ~Yara();
    
    private:
        bool dumpMatches; 

        YRX_COMPILER *compiler  = nullptr;
        YRX_RULES *rules        = nullptr;
        YRX_SCANNER *scanner    = nullptr;
        
        int active_callbacks     = 0;

        std::filesystem::path current_file;
        
        const char *current_rule    = nullptr;
        const char *current_pattern = nullptr;
        
        std::vector<uint8_t> current_file_data; 

        FullMatchCb on_full_match_callback = nullptr;

        FileMap results;
        
        static void onMatchingCb(const struct YRX_RULE *, void *);
        static void onPatternCb(const struct YRX_PATTERN *, void *);
        static void onPatternMatchesCb(const struct YRX_MATCH *, void *);

        bool dumpMatch(const struct YRX_MATCH *);
        

};
