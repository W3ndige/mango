#include <map>
#include <cstdint>
#include <sys/wait.h>
#include <vector>

extern "C" {
    #define namespace ns
    #include <yara_x.h>
    #undef namespace
}


using PatternMatch  = std::tuple<int, int>;
using PatternMap    = std::map<const char *, std::vector<PatternMatch>>;
using RuleMap       = std::map<const char *, PatternMap>;
using FileMap       = std::map<const char *, RuleMap>;

class Yara {  
    public:
        Yara(uint32_t);

        bool addSource(const char *);
        bool addSourceFromFile(const char *);
        bool initScanner();
        bool scanFile(const char *);
        
        void cleanResults();

        RuleMap getMatchedIdentifiersForFile(const char *); 

        ~Yara();
    
    private:
        YRX_COMPILER *compiler  = nullptr;
        YRX_RULES *rules        = nullptr;
        YRX_SCANNER *scanner    = nullptr;

        const char *current_file    = nullptr;
        const char *current_rule    = nullptr;
        const char *current_pattern = nullptr;

        FileMap results;
        
        static void onMatchingCb(const struct YRX_RULE *, void *);
        static void onPatternCb(const struct YRX_PATTERN *, void *);
        static void onPatternMatchesCb(const struct YRX_MATCH *, void *);
};
