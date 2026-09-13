#pragma once
#ifdef ELITF_USE_FMT
#include <fmt/format.h>
namespace elitf_format = fmt;
#else
#include <format>
namespace elitf_format = std;
#endif
