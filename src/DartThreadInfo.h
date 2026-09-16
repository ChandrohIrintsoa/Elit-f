#pragma once

const std::string& GetThreadOffsetName(intptr_t offset);
intptr_t GetThreadMaxOffset();

struct LeafFunctionInfo {
        std::string returnType;
        std::string params;
};
const LeafFunctionInfo* GetThreadLeafFunction(intptr_t offset);
