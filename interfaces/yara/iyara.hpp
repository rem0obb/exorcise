#pragma once

namespace YaraAnalysis
{
    class IYara
    {
    public:
        IYara(){};
        virtual ~IYara(){};
        virtual const void scan_file(const std::string &path, int flags, YR_CALLBACK_FUNC call_back, const bool verbose = false) const = 0;
        virtual const void scan_folder(const std::string &current_dir, int flags, YR_CALLBACK_FUNC call_back, const bool verbose = false) const = 0;
    };
}