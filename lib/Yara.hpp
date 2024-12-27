#include <cstdint>
#include <sys/wait.h>

extern "C" {
    #define namespace ns
    #include <yara_x.h>
    #undef namespace
}


struct ScanResult {
    bool initialized;
    bool exception;

    const char *file;
    const char *ruleName;
    const char *pattern;

};


class Yara {  
    public:
        Yara(uint32_t);

        bool add_source(const char *);
        bool add_source_from_file(const char *);
        bool init_scanner();
        bool scan_file(const char *);

        ~Yara();
    
    private:
        YRX_COMPILER *compiler  = nullptr;
        YRX_RULES *rules        = nullptr;
        YRX_SCANNER *scanner    = nullptr; 
        
        const char *current_file = nullptr;
        
        static void iterate_matches(const struct YRX_RULE *, ScanResult *);

        static void on_matching_cb(const struct YRX_RULE *, void *);
        static void on_pattern_cb(const struct YRX_PATTERN *, void *);
        static void on_pattern_iter_matches(const struct YRX_MATCH *, void *);
};
