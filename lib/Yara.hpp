#include <unordered_map>
#include <cstdint>
#include <sys/wait.h>
#include <vector>

extern "C" {
    #define namespace ns
    #include <yara_x.h>
    #undef namespace
}


class Yara {  
    public:
        Yara(uint32_t);

        bool add_source(const char *);
        bool add_source_from_file(const char *);
        bool init_scanner();
        bool scan_file(const char *);
        
        void clean_results();


        std::vector<const char *> getMatchedIdentifiersForFile(const char *); 


        ~Yara();
    
    private:
        YRX_COMPILER *compiler  = nullptr;
        YRX_RULES *rules        = nullptr;
        YRX_SCANNER *scanner    = nullptr;

        const char *current_file    = nullptr;
        
        std::unordered_map<const char *, std::vector<const char *>> results;
        
        static void on_matching_cb(const struct YRX_RULE *, void *);
        static void on_pattern_cb(const struct YRX_PATTERN *, void *);
        static void on_pattern_matches_cb(const struct YRX_MATCH *, void *);
};
