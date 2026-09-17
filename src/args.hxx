

#ifndef ARGS_HXX
#define ARGS_HXX

#define ARGS_VERSION "6.4.6"
#define ARGS_VERSION_MAJOR 6
#define ARGS_VERSION_MINOR 4
#define ARGS_VERSION_PATCH 6

#include <algorithm>
#include <iterator>
#include <exception>
#include <functional>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <type_traits>
#include <cstddef>
#include <cctype>
#include <iostream>

#if defined(_MSC_VER) && _MSC_VER <= 1800
#define noexcept
#endif

#ifdef ARGS_TESTNAMESPACE
namespace argstest
{
#else

namespace args
{
#endif
    template <typename Option>
    auto get(Option &option_) -> decltype(option_.Get())
    {
        return option_.Get();
    }

    inline std::string::size_type Glyphs(const std::string &string_)
    {
        std::string::size_type length = 0;
        for (const char c: string_)
        {
            if ((c & 0xc0) != 0x80)
            {
                ++length;
            }
        }
        return length;
    }

    template <typename It>
    inline std::vector<std::string> Wrap(It begin,
                                         It end,
                                         const std::string::size_type width,
                                         std::string::size_type firstlinewidth = 0,
                                         std::string::size_type firstlineindent = 0)
    {
        std::vector<std::string> output;
        std::string line(firstlineindent, ' ');
        bool empty = true;

        if (firstlinewidth == 0)
        {
            firstlinewidth = width;
        }

        auto currentwidth = firstlinewidth;

        for (auto it = begin; it != end; ++it)
        {
            if (it->empty())
            {
                continue;
            }

            if (*it == "\n")
            {
                if (!empty)
                {
                    output.push_back(line);
                    line.clear();
                    empty = true;
                    currentwidth = width;
                }

                continue;
            }

            auto itemsize = Glyphs(*it);
            if ((line.length() + 1 + itemsize) > currentwidth)
            {
                if (!empty)
                {
                    output.push_back(line);
                    line.clear();
                    empty = true;
                    currentwidth = width;
                }
            }

            if (itemsize > 0)
            {
                if (!empty)
                {
                    line += ' ';
                }

                line += *it;
                empty = false;
            }
        }

        if (!empty)
        {
            output.push_back(line);
        }

        return output;
    }

    namespace detail
    {
        template <typename T>
        std::string Join(const T& array, const std::string &delimiter)
        {
            std::string res;
            for (auto &element : array)
            {
                if (!res.empty())
                {
                    res += delimiter;
                }

                res += element;
            }

            return res;
        }
    }

    inline std::vector<std::string> Wrap(const std::string &in, const std::string::size_type width, std::string::size_type firstlinewidth = 0)
    {
        const auto newlineloc = in.find('\n');
        if (newlineloc != in.npos)
        {
            auto first = Wrap(std::string(in, 0, newlineloc), width);
            auto second = Wrap(std::string(in, newlineloc + 1), width);
            first.insert(
                std::end(first),
                std::make_move_iterator(std::begin(second)),
                std::make_move_iterator(std::end(second)));
            return first;
        }

        std::istringstream stream(in);
        std::string::size_type indent = 0;

        for (auto c : in)
        {
            if (!std::isspace(static_cast<unsigned char>(c)))
            {
                break;
            }
            ++indent;
        }

        return Wrap(std::istream_iterator<std::string>(stream), std::istream_iterator<std::string>(),
                    width, firstlinewidth, indent);
    }

#ifdef ARGS_NOEXCEPT
    enum class Error
    {
        None,
        Usage,
        Parse,
        Validation,
        Required,
        Map,
        Extra,
        Help,
        Subparser,
        Completion,
    };
#else
    class Error : public std::runtime_error
    {
        public:
            Error(const std::string &problem) : std::runtime_error(problem) {}
            virtual ~Error() {}
    };

    class UsageError : public Error
    {
        public:
            UsageError(const std::string &problem) : Error(problem) {}
            virtual ~UsageError() {}
    };

    class ParseError : public Error
    {
        public:
            ParseError(const std::string &problem) : Error(problem) {}
            virtual ~ParseError() {}
    };

    class ValidationError : public Error
    {
        public:
            ValidationError(const std::string &problem) : Error(problem) {}
            virtual ~ValidationError() {}
    };

    class RequiredError : public ValidationError
    {
        public:
            RequiredError(const std::string &problem) : ValidationError(problem) {}
            virtual ~RequiredError() {}
    };

    class MapError : public ParseError
    {
        public:
            MapError(const std::string &problem) : ParseError(problem) {}
            virtual ~MapError() {}
    };

    class ExtraError : public ParseError
    {
        public:
            ExtraError(const std::string &problem) : ParseError(problem) {}
            virtual ~ExtraError() {}
    };

    class Help : public Error
    {
        public:
            Help(const std::string &flag) : Error(flag) {}
            virtual ~Help() {}
    };

    class SubparserError : public Error
    {
        public:
            SubparserError() : Error("") {}
            virtual ~SubparserError() {}
    };

    class Completion : public Error
    {
        public:
            Completion(const std::string &flag) : Error(flag) {}
            virtual ~Completion() {}
    };
#endif

    struct EitherFlag
    {
        const bool isShort;
        const char shortFlag;
        const std::string longFlag;
        EitherFlag(const std::string &flag) : isShort(false), shortFlag(), longFlag(flag) {}
        EitherFlag(const char *flag) : isShort(false), shortFlag(), longFlag(flag) {}
        EitherFlag(const char flag) : isShort(true), shortFlag(flag), longFlag() {}

        static std::unordered_set<std::string> GetLong(std::initializer_list<EitherFlag> flags)
        {
            std::unordered_set<std::string>  longFlags;
            for (const EitherFlag &flag: flags)
            {
                if (!flag.isShort)
                {
                    longFlags.insert(flag.longFlag);
                }
            }
            return longFlags;
        }

        static std::unordered_set<char> GetShort(std::initializer_list<EitherFlag> flags)
        {
            std::unordered_set<char>  shortFlags;
            for (const EitherFlag &flag: flags)
            {
                if (flag.isShort)
                {
                    shortFlags.insert(flag.shortFlag);
                }
            }
            return shortFlags;
        }

        std::string str() const
        {
            return isShort ? std::string(1, shortFlag) : longFlag;
        }

        std::string str(const std::string &shortPrefix, const std::string &longPrefix) const
        {
            return isShort ? shortPrefix + std::string(1, shortFlag) : longPrefix + longFlag;
        }
    };



    class Matcher
    {
        private:
            const std::unordered_set<char> shortFlags;
            const std::unordered_set<std::string> longFlags;

        public:
            template <typename ShortIt, typename LongIt>
            Matcher(ShortIt shortFlagsStart, ShortIt shortFlagsEnd, LongIt longFlagsStart, LongIt longFlagsEnd) :
                shortFlags(shortFlagsStart, shortFlagsEnd),
                longFlags(longFlagsStart, longFlagsEnd)
            {
                if (shortFlags.empty() && longFlags.empty())
                {
#ifndef ARGS_NOEXCEPT
                    throw UsageError("empty Matcher");
#endif
                }
            }

#ifdef ARGS_NOEXCEPT
            Error GetError() const noexcept
            {
                return shortFlags.empty() && longFlags.empty() ? Error::Usage : Error::None;
            }
#endif

            template <typename Short, typename Long>
            Matcher(Short &&shortIn, Long &&longIn) :
                Matcher(std::begin(shortIn), std::end(shortIn), std::begin(longIn), std::end(longIn))
            {}

            Matcher(std::initializer_list<EitherFlag> in) :
                Matcher(EitherFlag::GetShort(in), EitherFlag::GetLong(in)) {}

            Matcher(Matcher &&other) noexcept : shortFlags(std::move(other.shortFlags)), longFlags(std::move(other.longFlags))
            {}

            ~Matcher() {}

            bool Match(const char flag) const
            {
                return shortFlags.find(flag) != shortFlags.end();
            }

            bool Match(const std::string &flag) const
            {
                return longFlags.find(flag) != longFlags.end();
            }

            bool Match(const EitherFlag &flag) const
            {
                return flag.isShort ? Match(flag.shortFlag) : Match(flag.longFlag);
            }

            std::vector<EitherFlag> GetFlagStrings() const
            {
                std::vector<EitherFlag> flagStrings;
                flagStrings.reserve(shortFlags.size() + longFlags.size());
                for (const char flag: shortFlags)
                {
                    flagStrings.emplace_back(flag);
                }
                for (const std::string &flag: longFlags)
                {
                    flagStrings.emplace_back(flag);
                }
                return flagStrings;
            }

            EitherFlag GetLongOrAny() const
            {
                if (!longFlags.empty())
                {
                    return *longFlags.begin();
                }

                if (!shortFlags.empty())
                {
                    return *shortFlags.begin();
                }

                return ' ';
            }

            EitherFlag GetShortOrAny() const
            {
                if (!shortFlags.empty())
                {
                    return *shortFlags.begin();
                }

                if (!longFlags.empty())
                {
                    return *longFlags.begin();
                }

                return ' ';
            }
    };

    enum class Options
    {
        None = 0x0,

        Single = 0x01,

        Required = 0x02,

        HiddenFromUsage = 0x04,

        HiddenFromDescription = 0x08,

        Global = 0x10,

        KickOut = 0x20,

        HiddenFromCompletion = 0x40,

        Hidden = HiddenFromUsage | HiddenFromDescription | HiddenFromCompletion,
    };

    inline Options operator | (Options lhs, Options rhs)
    {
        return static_cast<Options>(static_cast<int>(lhs) | static_cast<int>(rhs));
    }

    inline Options operator & (Options lhs, Options rhs)
    {
        return static_cast<Options>(static_cast<int>(lhs) & static_cast<int>(rhs));
    }

    class FlagBase;
    class PositionalBase;
    class Command;
    class ArgumentParser;

    struct HelpParams
    {
        unsigned int width = 80;
        unsigned int progindent = 2;
        unsigned int progtailindent = 4;
        unsigned int descriptionindent = 4;
        unsigned int flagindent = 6;
        unsigned int helpindent = 40;
        unsigned int eachgroupindent = 2;

        unsigned int gutter = 1;

        bool showTerminator = true;

        bool showProglineOptions = true;

        bool showProglinePositionals = true;

        std::string shortPrefix;

        std::string longPrefix;

        std::string shortSeparator;

        std::string longSeparator;

        std::string programName;

        bool showCommandChildren = false;

        bool showCommandFullHelp = false;

        std::string proglineOptions = "{OPTIONS}";

        std::string proglineCommand = "COMMAND";

        std::string proglineValueOpen = " <";

        std::string proglineValueClose = ">";

        std::string proglineRequiredOpen = "";

        std::string proglineRequiredClose = "";

        std::string proglineNonrequiredOpen = "[";

        std::string proglineNonrequiredClose = "]";

        bool proglineShowFlags = false;

        bool proglinePreferShortFlags = false;

        std::string usageString;

        std::string optionsString = "OPTIONS:";

        bool useValueNameOnce = false;

        bool showValueName = true;

        bool addNewlineBeforeDescription = false;

        std::string valueOpen = "[";

        std::string valueClose = "]";

        bool addChoices = false;

        std::string choiceString = "\nOne of: ";

        bool addDefault = false;

        std::string defaultString = "\nDefault: ";
    };

    struct Nargs
    {
        const size_t min;
        const size_t max;

        Nargs(size_t min_, size_t max_) : min{min_}, max{max_}
        {
#ifndef ARGS_NOEXCEPT
            if (max < min)
            {
                throw UsageError("Nargs: max > min");
            }
#endif
        }

        Nargs(size_t num_) : min{num_}, max{num_}
        {
        }

        friend bool operator == (const Nargs &lhs, const Nargs &rhs)
        {
            return lhs.min == rhs.min && lhs.max == rhs.max;
        }

        friend bool operator != (const Nargs &lhs, const Nargs &rhs)
        {
            return !(lhs == rhs);
        }
    };

    class Base
    {
        private:
            Options options = {};

        protected:
            bool matched = false;
            const std::string help;
#ifdef ARGS_NOEXCEPT
            mutable Error error = Error::None;
            mutable std::string errorMsg;
#endif

        public:
            Base(const std::string &help_, Options options_ = {}) : options(options_), help(help_) {}
            virtual ~Base() {}

            Options GetOptions() const noexcept
            {
                return options;
            }

            bool IsRequired() const noexcept
            {
                return (GetOptions() & Options::Required) != Options::None;
            }

            virtual bool Matched() const noexcept
            {
                return matched;
            }

            virtual void Validate(const std::string &, const std::string &) const
            {
            }

            operator bool() const noexcept
            {
                return Matched();
            }

            virtual std::vector<std::tuple<std::string, std::string, unsigned>> GetDescription(const HelpParams &, const unsigned indentLevel) const
            {
                std::tuple<std::string, std::string, unsigned> description;
                std::get<1>(description) = help;
                std::get<2>(description) = indentLevel;
                return { std::move(description) };
            }

            virtual std::vector<Command*> GetCommands()
            {
                return {};
            }

            virtual bool IsGroup() const
            {
                return false;
            }

            virtual FlagBase *Match(const EitherFlag &)
            {
                return nullptr;
            }

            virtual PositionalBase *GetNextPositional()
            {
                return nullptr;
            }

            virtual std::vector<FlagBase*> GetAllFlags()
            {
                return {};
            }

            virtual bool HasFlag() const
            {
                return false;
            }

            virtual bool HasPositional() const
            {
                return false;
            }

            virtual bool HasCommand() const
            {
                return false;
            }

            virtual std::vector<std::string> GetProgramLine(const HelpParams &) const
            {
                return {};
            }

            void KickOut(bool kickout_) noexcept
            {
                if (kickout_)
                {
                    options = options | Options::KickOut;
                }
                else
                {
                    options = static_cast<Options>(static_cast<int>(options) & ~static_cast<int>(Options::KickOut));
                }
            }

            bool KickOut() const noexcept
            {
                return (options & Options::KickOut) != Options::None;
            }

            virtual void Reset() noexcept
            {
                matched = false;
#ifdef ARGS_NOEXCEPT
                error = Error::None;
                errorMsg.clear();
#endif
            }

#ifdef ARGS_NOEXCEPT
            virtual Error GetError() const
            {
                return error;
            }

            virtual std::string GetErrorMsg() const
            {
                return errorMsg;
            }
#endif
    };

    class NamedBase : public Base
    {
        protected:
            const std::string name;
            bool kickout = false;
            std::string defaultString;
            bool defaultStringManual = false;
            std::vector<std::string> choicesStrings;
            bool choicesStringManual = false;

            virtual std::string GetDefaultString(const HelpParams&) const { return {}; }

            virtual std::vector<std::string> GetChoicesStrings(const HelpParams&) const { return {}; }

            virtual std::string GetNameString(const HelpParams&) const { return Name(); }

            void AddDescriptionPostfix(std::string &dest, const bool isManual, const std::string &manual, bool isGenerated, const std::string &generated, const std::string &str) const
            {
                if (isManual && !manual.empty())
                {
                    dest += str;
                    dest += manual;
                }
                else if (!isManual && isGenerated && !generated.empty())
                {
                    dest += str;
                    dest += generated;
                }
            }

        public:
            NamedBase(const std::string &name_, const std::string &help_, Options options_ = {}) : Base(help_, options_), name(name_) {}
            virtual ~NamedBase() {}

            void HelpDefault(const std::string &str)
            {
                defaultStringManual = true;
                defaultString = str;
            }

            std::string HelpDefault(const HelpParams &params) const
            {
                return defaultStringManual ? defaultString : GetDefaultString(params);
            }

            void HelpChoices(const std::vector<std::string> &array)
            {
                choicesStringManual = true;
                choicesStrings = array;
            }

            std::vector<std::string> HelpChoices(const HelpParams &params) const
            {
                return choicesStringManual ? choicesStrings : GetChoicesStrings(params);
            }

            virtual std::vector<std::tuple<std::string, std::string, unsigned>> GetDescription(const HelpParams &params, const unsigned indentLevel) const override
            {
                std::tuple<std::string, std::string, unsigned> description;
                std::get<0>(description) = GetNameString(params);
                std::get<1>(description) = help;
                std::get<2>(description) = indentLevel;

                AddDescriptionPostfix(std::get<1>(description), choicesStringManual, detail::Join(choicesStrings, ", "), params.addChoices, detail::Join(GetChoicesStrings(params), ", "), params.choiceString);
                AddDescriptionPostfix(std::get<1>(description), defaultStringManual, defaultString, params.addDefault, GetDefaultString(params), params.defaultString);

                return { std::move(description) };
            }

            virtual std::string Name() const
            {
                return name;
            }
    };

    namespace detail
    {
        template<typename T>
        using vector = std::vector<T, std::allocator<T>>;

        template<typename K, typename T>
        using unordered_map = std::unordered_map<K, T, std::hash<K>,
            std::equal_to<K>, std::allocator<std::pair<const K, T> > >;

        template<typename S, typename T>
        class is_streamable
        {
            template<typename SS, typename TT>
            static auto test(int)
            -> decltype( std::declval<SS&>() << std::declval<TT>(), std::true_type() );

            template<typename, typename>
            static auto test(...) -> std::false_type;

        public:
            using type = decltype(test<S,T>(0));
        };

        template <typename T>
        using IsConvertableToString = typename is_streamable<std::ostringstream, T>::type;

        template <typename T>
        typename std::enable_if<IsConvertableToString<T>::value, std::string>::type
        ToString(const T &value)
        {
            std::ostringstream s;
            s << value;
            return s.str();
        }

        template <typename T>
        typename std::enable_if<!IsConvertableToString<T>::value, std::string>::type
        ToString(const T &)
        {
            return {};
        }

        template <typename T>
        std::vector<std::string> MapKeysToStrings(const T &map)
        {
            std::vector<std::string> res;
            using K = typename std::decay<decltype(std::begin(map)->first)>::type;
            if (IsConvertableToString<K>::value)
            {
                for (const auto &p : map)
                {
                    res.push_back(detail::ToString(p.first));
                }

                std::sort(res.begin(), res.end());
            }
            return res;
        }
    }

    class FlagBase : public NamedBase
    {
        protected:
            const Matcher matcher;

            virtual std::string GetNameString(const HelpParams &params) const override
            {
                const std::string postfix = !params.showValueName || NumberOfArguments() == 0 ? std::string() : Name();
                std::string flags;
                const auto flagStrings = matcher.GetFlagStrings();
                const bool useValueNameOnce = flagStrings.size() == 1 ? false : params.useValueNameOnce;
                for (auto it = flagStrings.begin(); it != flagStrings.end(); ++it)
                {
                    auto &flag = *it;
                    if (it != flagStrings.begin())
                    {
                        flags += ", ";
                    }

                    flags += flag.isShort ? params.shortPrefix : params.longPrefix;
                    flags += flag.str();

                    if (!postfix.empty() && (!useValueNameOnce || it + 1 == flagStrings.end()))
                    {
                        flags += flag.isShort ? params.shortSeparator : params.longSeparator;
                        flags += params.valueOpen + postfix + params.valueClose;
                    }
                }

                return flags;
            }

        public:
            FlagBase(const std::string &name_, const std::string &help_, Matcher &&matcher_, const bool extraError_ = false) : NamedBase(name_, help_, extraError_ ? Options::Single : Options()), matcher(std::move(matcher_)) {}

            FlagBase(const std::string &name_, const std::string &help_, Matcher &&matcher_, Options options_) : NamedBase(name_, help_, options_), matcher(std::move(matcher_)) {}

            virtual ~FlagBase() {}

            virtual FlagBase *Match(const EitherFlag &flag) override
            {
                if (matcher.Match(flag))
                {
                    if ((GetOptions() & Options::Single) != Options::None && matched)
                    {
                        std::ostringstream problem;
                        problem << "Flag '" << flag.str() << "' was passed multiple times, but is only allowed to be passed once";
#ifdef ARGS_NOEXCEPT
                        error = Error::Extra;
                        errorMsg = problem.str();
#else
                        throw ExtraError(problem.str());
#endif
                    }
                    matched = true;
                    return this;
                }
                return nullptr;
            }

            virtual std::vector<FlagBase*> GetAllFlags() override
            {
                return { this };
            }

            const Matcher &GetMatcher() const
            {
                return matcher;
            }

            virtual void Validate(const std::string &shortPrefix, const std::string &longPrefix) const override
            {
                if (!Matched() && IsRequired())
                {
                        std::ostringstream problem;
                        problem << "Flag '" << matcher.GetLongOrAny().str(shortPrefix, longPrefix) << "' is required";
#ifdef ARGS_NOEXCEPT
                        error = Error::Required;
                        errorMsg = problem.str();
#else
                        throw RequiredError(problem.str());
#endif
                }
            }

            virtual std::vector<std::string> GetProgramLine(const HelpParams &params) const override
            {
                if (!params.proglineShowFlags)
                {
                    return {};
                }

                const std::string postfix = NumberOfArguments() == 0 ? std::string() : Name();
                const EitherFlag flag = params.proglinePreferShortFlags ? matcher.GetShortOrAny() : matcher.GetLongOrAny();
                std::string res = flag.str(params.shortPrefix, params.longPrefix);
                if (!postfix.empty())
                {
                    res += params.proglineValueOpen + postfix + params.proglineValueClose;
                }

                return { IsRequired() ? params.proglineRequiredOpen + res + params.proglineRequiredClose
                                      : params.proglineNonrequiredOpen + res + params.proglineNonrequiredClose };
            }

            virtual bool HasFlag() const override
            {
                return true;
            }

#ifdef ARGS_NOEXCEPT
            virtual Error GetError() const override
            {
                const auto nargs = NumberOfArguments();
                if (nargs.min > nargs.max)
                {
                    return Error::Usage;
                }

                const auto matcherError = matcher.GetError();
                if (matcherError != Error::None)
                {
                    return matcherError;
                }

                return error;
            }
#endif

            virtual Nargs NumberOfArguments() const noexcept = 0;

            virtual void ParseValue(const std::vector<std::string> &value) = 0;
    };

    class ValueFlagBase : public FlagBase
    {
        public:
            ValueFlagBase(const std::string &name_, const std::string &help_, Matcher &&matcher_, const bool extraError_ = false) : FlagBase(name_, help_, std::move(matcher_), extraError_) {}
            ValueFlagBase(const std::string &name_, const std::string &help_, Matcher &&matcher_, Options options_) : FlagBase(name_, help_, std::move(matcher_), options_) {}
            virtual ~ValueFlagBase() {}

            virtual Nargs NumberOfArguments() const noexcept override
            {
                return 1;
            }
    };

    class CompletionFlag : public ValueFlagBase
    {
        public:
            std::vector<std::string> reply;
            size_t cword = 0;
            std::string syntax;

            template <typename GroupClass>
            CompletionFlag(GroupClass &group_, Matcher &&matcher_): ValueFlagBase("completion", "completion flag", std::move(matcher_), Options::Hidden)
            {
                group_.AddCompletion(*this);
            }

            virtual ~CompletionFlag() {}

            virtual Nargs NumberOfArguments() const noexcept override
            {
                return 2;
            }

            virtual void ParseValue(const std::vector<std::string> &value_) override
            {
                syntax = value_.at(0);
                std::istringstream(value_.at(1)) >> cword;
            }

            std::string Get() noexcept
            {
                return detail::Join(reply, "\n");
            }

            virtual void Reset() noexcept override
            {
                ValueFlagBase::Reset();
                cword = 0;
                syntax.clear();
                reply.clear();
            }
    };


    class PositionalBase : public NamedBase
    {
        protected:
            bool ready;

        public:
            PositionalBase(const std::string &name_, const std::string &help_, Options options_ = {}) : NamedBase(name_, help_, options_), ready(true) {}
            virtual ~PositionalBase() {}

            bool Ready()
            {
                return ready;
            }

            virtual void ParseValue(const std::string &value_) = 0;

            virtual void Reset() noexcept override
            {
                matched = false;
                ready = true;
#ifdef ARGS_NOEXCEPT
                error = Error::None;
                errorMsg.clear();
#endif
            }

            virtual PositionalBase *GetNextPositional() override
            {
                return Ready() ? this : nullptr;
            }

            virtual bool HasPositional() const override
            {
                return true;
            }

            virtual std::vector<std::string> GetProgramLine(const HelpParams &params) const override
            {
                return { IsRequired() ? params.proglineRequiredOpen + Name() + params.proglineRequiredClose
                                      : params.proglineNonrequiredOpen + Name() + params.proglineNonrequiredClose };
            }

            virtual void Validate(const std::string &, const std::string &) const override
            {
                if (IsRequired() && !Matched())
                {
                    std::ostringstream problem;
                    problem << "Option '" << Name() << "' is required";
#ifdef ARGS_NOEXCEPT
                    error = Error::Required;
                    errorMsg = problem.str();
#else
                    throw RequiredError(problem.str());
#endif
                }
            }
    };

    class Group : public Base
    {
        private:
            std::vector<Base*> children;
            std::function<bool(const Group &)> validator;

        public:
            struct Validators
            {
                static bool Xor(const Group &group)
                {
                    return group.MatchedChildren() == 1;
                }

                static bool AtLeastOne(const Group &group)
                {
                    return group.MatchedChildren() >= 1;
                }

                static bool AtMostOne(const Group &group)
                {
                    return group.MatchedChildren() <= 1;
                }

                static bool All(const Group &group)
                {
                    return group.Children().size() == group.MatchedChildren();
                }

                static bool AllOrNone(const Group &group)
                {
                    return (All(group) || None(group));
                }

                static bool AllChildGroups(const Group &group)
                {
                    return std::none_of(std::begin(group.Children()), std::end(group.Children()), [](const Base* child) -> bool {
                            return child->IsGroup() && !child->Matched();
                            });
                }

                static bool DontCare(const Group &)
                {
                    return true;
                }

                static bool CareTooMuch(const Group &)
                {
                    return false;
                }

                static bool None(const Group &group)
                {
                    return group.MatchedChildren() == 0;
                }
            };
            Group(const std::string &help_ = std::string(), const std::function<bool(const Group &)> &validator_ = Validators::DontCare, Options options_ = {}) : Base(help_, options_), validator(validator_) {}
            Group(Group &group_, const std::string &help_ = std::string(), const std::function<bool(const Group &)> &validator_ = Validators::DontCare, Options options_ = {}) : Base(help_, options_), validator(validator_)
            {
                group_.Add(*this);
            }
            virtual ~Group() {}

            void Add(Base &child)
            {
                children.emplace_back(&child);
            }

            const std::vector<Base *> &Children() const
            {
                return children;
            }

            virtual FlagBase *Match(const EitherFlag &flag) override
            {
                for (Base *child: Children())
                {
                    if (FlagBase *match = child->Match(flag))
                    {
                        return match;
                    }
                }
                return nullptr;
            }

            virtual std::vector<FlagBase*> GetAllFlags() override
            {
                std::vector<FlagBase*> res;
                for (Base *child: Children())
                {
                    auto childRes = child->GetAllFlags();
                    res.insert(res.end(), childRes.begin(), childRes.end());
                }
                return res;
            }

            virtual void Validate(const std::string &shortPrefix, const std::string &longPrefix) const override
            {
                for (Base *child: Children())
                {
                    child->Validate(shortPrefix, longPrefix);
                }
            }

            virtual PositionalBase *GetNextPositional() override
            {
                for (Base *child: Children())
                {
                    if (auto next = child->GetNextPositional())
                    {
                        return next;
                    }
                }
                return nullptr;
            }

            virtual bool HasFlag() const override
            {
                return std::any_of(Children().begin(), Children().end(), [](Base *child) { return child->HasFlag(); });
            }

            virtual bool HasPositional() const override
            {
                return std::any_of(Children().begin(), Children().end(), [](Base *child) { return child->HasPositional(); });
            }

            virtual bool HasCommand() const override
            {
                return std::any_of(Children().begin(), Children().end(), [](Base *child) { return child->HasCommand(); });
            }

            std::vector<Base *>::size_type MatchedChildren() const
            {
                return static_cast<std::vector<Base *>::size_type>(
                        std::count_if(std::begin(Children()), std::end(Children()), [](const Base *child){return child->Matched();}));
            }

            virtual bool Matched() const noexcept override
            {
                return validator(*this);
            }

            bool Get() const
            {
                return Matched();
            }

            virtual std::vector<std::tuple<std::string, std::string, unsigned>> GetDescription(const HelpParams &params, const unsigned int indent) const override
            {
                std::vector<std::tuple<std::string, std::string, unsigned int>> descriptions;

                unsigned addindent = 0;
                if (!help.empty())
                {
                    descriptions.emplace_back(help, "", indent);
                    addindent = 1;
                }

                for (Base *child: Children())
                {
                    if ((child->GetOptions() & Options::HiddenFromDescription) != Options::None)
                    {
                        continue;
                    }

                    auto groupDescriptions = child->GetDescription(params, indent + addindent);
                    descriptions.insert(
                        std::end(descriptions),
                        std::make_move_iterator(std::begin(groupDescriptions)),
                        std::make_move_iterator(std::end(groupDescriptions)));
                }
                return descriptions;
            }

            virtual std::vector<std::string> GetProgramLine(const HelpParams &params) const override
            {
                std::vector <std::string> names;
                for (Base *child: Children())
                {
                    if ((child->GetOptions() & Options::HiddenFromUsage) != Options::None)
                    {
                        continue;
                    }

                    auto groupNames = child->GetProgramLine(params);
                    names.insert(
                        std::end(names),
                        std::make_move_iterator(std::begin(groupNames)),
                        std::make_move_iterator(std::end(groupNames)));
                }
                return names;
            }

            virtual std::vector<Command*> GetCommands() override
            {
                std::vector<Command*> res;
                for (const auto &child : Children())
                {
                    auto subparsers = child->GetCommands();
                    res.insert(std::end(res), std::begin(subparsers), std::end(subparsers));
                }
                return res;
            }

            virtual bool IsGroup() const override
            {
                return true;
            }

            virtual void Reset() noexcept override
            {
                Base::Reset();

                for (auto &child: Children())
                {
                    child->Reset();
                }
#ifdef ARGS_NOEXCEPT
                error = Error::None;
                errorMsg.clear();
#endif
            }

#ifdef ARGS_NOEXCEPT
            virtual Error GetError() const override
            {
                if (error != Error::None)
                {
                    return error;
                }

                auto it = std::find_if(Children().begin(), Children().end(), [](const Base *child){return child->GetError() != Error::None;});
                if (it == Children().end())
                {
                    return Error::None;
                } else
                {
                    return (*it)->GetError();
                }
            }

            virtual std::string GetErrorMsg() const override
            {
                if (error != Error::None)
                {
                    return errorMsg;
                }

                auto it = std::find_if(Children().begin(), Children().end(), [](const Base *child){return child->GetError() != Error::None;});
                if (it == Children().end())
                {
                    return "";
                } else
                {
                    return (*it)->GetErrorMsg();
                }
            }
#endif

    };

    class GlobalOptions : public Group
    {
        public:
            GlobalOptions(Group &base, Base &options_) : Group(base, {}, Group::Validators::DontCare, Options::Global)
            {
                Add(options_);
            }
    };

    class Subparser : public Group
    {
        private:
            std::vector<std::string> args;
            std::vector<std::string> kicked;
            ArgumentParser *parser = nullptr;
            const HelpParams &helpParams;
            const Command &command;
            bool isParsed = false;

        public:
            Subparser(std::vector<std::string> args_, ArgumentParser &parser_, const Command &command_, const HelpParams &helpParams_)
                : Group({}, Validators::AllChildGroups), args(std::move(args_)), parser(&parser_), helpParams(helpParams_), command(command_)
            {
            }

            Subparser(const Command &command_, const HelpParams &helpParams_) : Group({}, Validators::AllChildGroups), helpParams(helpParams_), command(command_)
            {
            }

            Subparser(const Subparser&) = delete;
            Subparser(Subparser&&) = delete;
            Subparser &operator = (const Subparser&) = delete;
            Subparser &operator = (Subparser&&) = delete;

            const Command &GetCommand()
            {
                return command;
            }

            bool IsParsed() const
            {
                return isParsed;
            }

            void Parse();

            const std::vector<std::string> &KickedOut() const noexcept
            {
                return kicked;
            }
    };

    class Command : public Group
    {
        private:
            friend class Subparser;

            std::string name;
            std::string help;
            std::string description;
            std::string epilog;
            std::string proglinePostfix;

            std::function<void(Subparser&)> parserCoroutine;
            bool commandIsRequired = true;
            Command *selectedCommand = nullptr;

            mutable std::vector<std::tuple<std::string, std::string, unsigned>> subparserDescription;
            mutable std::vector<std::string> subparserProgramLine;
            mutable bool subparserHasFlag = false;
            mutable bool subparserHasPositional = false;
            mutable bool subparserHasCommand = false;
#ifdef ARGS_NOEXCEPT
            mutable Error subparserError = Error::None;
#endif
            mutable Subparser *subparser = nullptr;

        protected:

            class RaiiSubparser
            {
                public:
                    RaiiSubparser(ArgumentParser &parser_, std::vector<std::string> args_);
                    RaiiSubparser(const Command &command_, const HelpParams &params_);

                    ~RaiiSubparser()
                    {
                        command.subparser = oldSubparser;
                    }

                    Subparser &Parser()
                    {
                        return parser;
                    }

                private:
                    const Command &command;
                    Subparser parser;
                    Subparser *oldSubparser;
            };

            Command() = default;

            std::function<void(Subparser&)> &GetCoroutine()
            {
                return selectedCommand != nullptr ? selectedCommand->GetCoroutine() : parserCoroutine;
            }

            Command &SelectedCommand()
            {
                Command *res = this;
                while (res->selectedCommand != nullptr)
                {
                    res = res->selectedCommand;
                }

                return *res;
            }

            const Command &SelectedCommand() const
            {
                const Command *res = this;
                while (res->selectedCommand != nullptr)
                {
                    res = res->selectedCommand;
                }

                return *res;
            }

            void UpdateSubparserHelp(const HelpParams &params) const
            {
                if (parserCoroutine)
                {
                    RaiiSubparser coro(*this, params);
#ifndef ARGS_NOEXCEPT
                    try
                    {
                        parserCoroutine(coro.Parser());
                    }
                    catch (args::SubparserError&)
                    {
                    }
#else
                    parserCoroutine(coro.Parser());
#endif
                }
            }

        public:
            Command(Group &base_, std::string name_, std::string help_, std::function<void(Subparser&)> coroutine_ = {})
                : name(std::move(name_)), help(std::move(help_)), parserCoroutine(std::move(coroutine_))
            {
                base_.Add(*this);
            }

            const std::string &ProglinePostfix() const
            { return proglinePostfix; }

            void ProglinePostfix(const std::string &proglinePostfix_)
            { this->proglinePostfix = proglinePostfix_; }

            const std::string &Description() const
            { return description; }

            void Description(const std::string &description_)
            { this->description = description_; }

            const std::string &Epilog() const
            { return epilog; }

            void Epilog(const std::string &epilog_)
            { this->epilog = epilog_; }

            const std::string &Name() const
            { return name; }

            const std::string &Help() const
            { return help; }

            void RequireCommand(bool value)
            { commandIsRequired = value; }

            virtual bool IsGroup() const override
            { return false; }

            virtual bool Matched() const noexcept override
            { return Base::Matched(); }

            operator bool() const noexcept
            { return Matched(); }

            void Match() noexcept
            { matched = true; }

            void SelectCommand(Command *c) noexcept
            {
                selectedCommand = c;

                if (c != nullptr)
                {
                    c->Match();
                }
            }

            virtual FlagBase *Match(const EitherFlag &flag) override
            {
                if (selectedCommand != nullptr)
                {
                    if (auto *res = selectedCommand->Match(flag))
                    {
                        return res;
                    }

                    for (auto *child: Children())
                    {
                        if ((child->GetOptions() & Options::Global) != Options::None)
                        {
                            if (auto *res = child->Match(flag))
                            {
                                return res;
                            }
                        }
                    }

                    return nullptr;
                }

                if (subparser != nullptr)
                {
                    return subparser->Match(flag);
                }

                return Matched() ? Group::Match(flag) : nullptr;
            }

            virtual std::vector<FlagBase*> GetAllFlags() override
            {
                std::vector<FlagBase*> res;

                if (!Matched())
                {
                    return res;
                }

                for (auto *child: Children())
                {
                    if (selectedCommand == nullptr || (child->GetOptions() & Options::Global) != Options::None)
                    {
                        auto childFlags = child->GetAllFlags();
                        res.insert(res.end(), childFlags.begin(), childFlags.end());
                    }
                }

                if (selectedCommand != nullptr)
                {
                    auto childFlags = selectedCommand->GetAllFlags();
                    res.insert(res.end(), childFlags.begin(), childFlags.end());
                }

                if (subparser != nullptr)
                {
                    auto childFlags = subparser->GetAllFlags();
                    res.insert(res.end(), childFlags.begin(), childFlags.end());
                }

                return res;
            }

            virtual PositionalBase *GetNextPositional() override
            {
                if (selectedCommand != nullptr)
                {
                    if (auto *res = selectedCommand->GetNextPositional())
                    {
                        return res;
                    }

                    for (auto *child: Children())
                    {
                        if ((child->GetOptions() & Options::Global) != Options::None)
                        {
                            if (auto *res = child->GetNextPositional())
                            {
                                return res;
                            }
                        }
                    }

                    return nullptr;
                }

                if (subparser != nullptr)
                {
                    return subparser->GetNextPositional();
                }

                return Matched() ? Group::GetNextPositional() : nullptr;
            }

            virtual bool HasFlag() const override
            {
                return subparserHasFlag || Group::HasFlag();
            }

            virtual bool HasPositional() const override
            {
                return subparserHasPositional || Group::HasPositional();
            }

            virtual bool HasCommand() const override
            {
                return true;
            }

            std::vector<std::string> GetCommandProgramLine(const HelpParams &params) const
            {
                UpdateSubparserHelp(params);

                std::vector<std::string> res;

                if ((subparserHasFlag || Group::HasFlag()) && params.showProglineOptions && !params.proglineShowFlags)
                {
                    res.push_back(params.proglineOptions);
                }

                auto group_res = Group::GetProgramLine(params);
                std::move(std::move(group_res).begin(), std::move(group_res).end(), std::back_inserter(res));

                res.insert(res.end(), subparserProgramLine.begin(), subparserProgramLine.end());

                if (!params.proglineCommand.empty() && (Group::HasCommand() || subparserHasCommand))
                {
                    res.insert(res.begin(), commandIsRequired ? params.proglineCommand : "[" + params.proglineCommand + "]");
                }

                if (!Name().empty())
                {
                    res.insert(res.begin(), Name());
                }

                if (!ProglinePostfix().empty())
                {
                    std::string line;
                    for (auto c : ProglinePostfix())
                    {
                        if (std::isspace(static_cast<unsigned char>(c)))
                        {
                            if (!line.empty())
                            {
                                res.push_back(line);
                                line.clear();
                            }

                            if (c == '\n')
                            {
                                res.push_back("\n");
                            }
                        }
                        else
                        {
                            line += c;
                        }
                    }

                    if (!line.empty())
                    {
                        res.push_back(line);
                    }
                }

                return res;
            }

            virtual std::vector<std::string> GetProgramLine(const HelpParams &params) const override
            {
                if (!Matched())
                {
                    return {};
                }

                return GetCommandProgramLine(params);
            }

            virtual std::vector<Command*> GetCommands() override
            {
                if (selectedCommand != nullptr)
                {
                    return selectedCommand->GetCommands();
                }

                if (Matched())
                {
                    return Group::GetCommands();
                }

                return { this };
            }

            virtual std::vector<std::tuple<std::string, std::string, unsigned>> GetDescription(const HelpParams &params, const unsigned int indent) const override
            {
                std::vector<std::tuple<std::string, std::string, unsigned>> descriptions;
                unsigned addindent = 0;

                UpdateSubparserHelp(params);

                if (!Matched())
                {
                    if (params.showCommandFullHelp)
                    {
                        std::ostringstream s;
                        bool empty = true;
                        for (const auto &progline: GetCommandProgramLine(params))
                        {
                            if (!empty)
                            {
                                s << ' ';
                            }
                            else
                            {
                                empty = false;
                            }

                            s << progline;
                        }

                        descriptions.emplace_back(s.str(), "", indent);
                    }
                    else
                    {
                        descriptions.emplace_back(Name(), help, indent);
                    }

                    if (!params.showCommandChildren && !params.showCommandFullHelp)
                    {
                        return descriptions;
                    }

                    addindent = 1;
                }

                if (params.showCommandFullHelp && !Matched())
                {
                    descriptions.emplace_back("", "", indent + addindent);
                    descriptions.emplace_back(Description().empty() ? Help() : Description(), "", indent + addindent);
                    descriptions.emplace_back("", "", indent + addindent);
                }

                for (Base *child: Children())
                {
                    if ((child->GetOptions() & Options::HiddenFromDescription) != Options::None)
                    {
                        continue;
                    }

                    auto groupDescriptions = child->GetDescription(params, indent + addindent);
                    descriptions.insert(
                                        std::end(descriptions),
                                        std::make_move_iterator(std::begin(groupDescriptions)),
                                        std::make_move_iterator(std::end(groupDescriptions)));
                }

                for (auto childDescription: subparserDescription)
                {
                    std::get<2>(childDescription) += indent + addindent;
                    descriptions.push_back(std::move(childDescription));
                }

                if (params.showCommandFullHelp && !Matched())
                {
                    descriptions.emplace_back("", "", indent + addindent);
                    if (!Epilog().empty())
                    {
                        descriptions.emplace_back(Epilog(), "", indent + addindent);
                        descriptions.emplace_back("", "", indent + addindent);
                    }
                }

                return descriptions;
            }

            virtual void Validate(const std::string &shortprefix, const std::string &longprefix) const override
            {
                if (!Matched())
                {
                    return;
                }

                auto onValidationError = [&]
                {
                    std::ostringstream problem;
                    problem << "Group validation failed somewhere!";
#ifdef ARGS_NOEXCEPT
                    error = Error::Validation;
                    errorMsg = problem.str();
#else
                    throw ValidationError(problem.str());
#endif
                };

                for (Base *child: Children())
                {
                    if (child->IsGroup() && !child->Matched())
                    {
                        onValidationError();
                    }

                    child->Validate(shortprefix, longprefix);
                }

                if (subparser != nullptr)
                {
                    subparser->Validate(shortprefix, longprefix);
                    if (!subparser->Matched())
                    {
                        onValidationError();
                    }
                }

                if (selectedCommand == nullptr && commandIsRequired && (Group::HasCommand() || subparserHasCommand))
                {
                    std::ostringstream problem;
                    problem << "Command is required";
#ifdef ARGS_NOEXCEPT
                    error = Error::Validation;
                    errorMsg = problem.str();
#else
                    throw ValidationError(problem.str());
#endif
                }
            }

            virtual void Reset() noexcept override
            {
                Group::Reset();
                selectedCommand = nullptr;
                subparserProgramLine.clear();
                subparserDescription.clear();
                subparserHasFlag = false;
                subparserHasPositional = false;
                subparserHasCommand = false;
#ifdef ARGS_NOEXCEPT
                subparserError = Error::None;
#endif
            }

#ifdef ARGS_NOEXCEPT
            virtual Error GetError() const override
            {
                if (!Matched())
                {
                    return Error::None;
                }

                if (error != Error::None)
                {
                    return error;
                }

                if (subparserError != Error::None)
                {
                    return subparserError;
                }

                return Group::GetError();
            }
#endif
    };

    class ArgumentParser : public Command
    {
        friend class Subparser;

        private:
            std::string longprefix;
            std::string shortprefix;

            std::string longseparator;

            std::string terminator;

            bool allowJoinedShortValue = true;
            bool allowJoinedLongValue = true;
            bool allowSeparateShortValue = true;
            bool allowSeparateLongValue = true;

            CompletionFlag *completion = nullptr;
            bool readCompletion = false;

        protected:
            enum class OptionType
            {
                LongFlag,
                ShortFlag,
                Positional
            };

            OptionType ParseOption(const std::string &s, bool allowEmpty = false)
            {
                if (s.find(longprefix) == 0 && (allowEmpty || s.length() > longprefix.length()))
                {
                    return OptionType::LongFlag;
                }

                if (s.find(shortprefix) == 0 && (allowEmpty || s.length() > shortprefix.length()))
                {
                    return OptionType::ShortFlag;
                }

                return OptionType::Positional;
            }

            template <typename It>
            bool Complete(FlagBase &flag, It it, It end)
            {
                auto nextIt = it;
                if (!readCompletion || (++nextIt != end))
                {
                    return false;
                }

                const auto &chunk = *it;
                for (auto &choice : flag.HelpChoices(helpParams))
                {
                    AddCompletionReply(chunk, choice);
                }

#ifndef ARGS_NOEXCEPT
                throw Completion(completion->Get());
#else
                return true;
#endif
            }

            template <typename It>
            std::string ParseArgsValues(FlagBase &flag, const std::string &arg, It &it, It end,
                                        const bool allowSeparate, const bool allowJoined,
                                        const bool hasJoined, const std::string &joinedArg,
                                        const bool canDiscardJoined, std::vector<std::string> &values)
            {
                values.clear();

                Nargs nargs = flag.NumberOfArguments();

                if (hasJoined && !allowJoined && nargs.min != 0)
                {
                    return "Flag '" + arg + "' was passed a joined argument, but these are disallowed";
                }

                if (hasJoined)
                {
                    if (!canDiscardJoined || nargs.max != 0)
                    {
                        values.push_back(joinedArg);
                    }
                } else if (!allowSeparate)
                {
                    if (nargs.min != 0)
                    {
                        return "Flag '" + arg + "' was passed a separate argument, but these are disallowed";
                    }
                } else
                {
                    auto valueIt = it;
                    ++valueIt;

                    while (valueIt != end &&
                           values.size() < nargs.max &&
                           (values.size() < nargs.min || ParseOption(*valueIt) == OptionType::Positional))
                    {
                        if (Complete(flag, valueIt, end))
                        {
                            it = end;
                            return "";
                        }

                        values.push_back(*valueIt);
                        ++it;
                        ++valueIt;
                    }
                }

                if (values.size() > nargs.max)
                {
                    return "Passed an argument into a non-argument flag: " + arg;
                } else if (values.size() < nargs.min)
                {
                    if (nargs.min == 1 && nargs.max == 1)
                    {
                        return "Flag '" + arg + "' requires an argument but received none";
                    } else if (nargs.min == 1)
                    {
                        return "Flag '" + arg + "' requires at least one argument but received none";
                    } else if (nargs.min != nargs.max)
                    {
                        return "Flag '" + arg + "' requires at least " + std::to_string(nargs.min) +
                               " arguments but received " + std::to_string(values.size());
                    } else
                    {
                        return "Flag '" + arg + "' requires " + std::to_string(nargs.min) +
                               " arguments but received " + std::to_string(values.size());
                    }
                }

                return {};
            }

            template <typename It>
            bool ParseLong(It &it, It end)
            {
                const auto &chunk = *it;
                const auto argchunk = chunk.substr(longprefix.size());
                const auto separator = longseparator.empty() ? argchunk.npos : argchunk.find(longseparator);
                const auto arg = (separator != argchunk.npos ?
                    std::string(argchunk, 0, separator)
                    : argchunk);
                const auto joined = (separator != argchunk.npos ?
                    argchunk.substr(separator + longseparator.size())
                    : std::string());

                if (auto flag = Match(arg))
                {
                    std::vector<std::string> values;
                    const std::string errorMessage = ParseArgsValues(*flag, arg, it, end, allowSeparateLongValue, allowJoinedLongValue,
                                                                     separator != argchunk.npos, joined, false, values);
                    if (!errorMessage.empty())
                    {
#ifndef ARGS_NOEXCEPT
                        throw ParseError(errorMessage);
#else
                        error = Error::Parse;
                        errorMsg = errorMessage;
                        return false;
#endif
                    }

                    if (!readCompletion)
                    {
                        flag->ParseValue(values);
                    }

                    if (flag->KickOut())
                    {
                        ++it;
                        return false;
                    }
                } else
                {
                    const std::string errorMessage("Flag could not be matched: " + arg);
#ifndef ARGS_NOEXCEPT
                    throw ParseError(errorMessage);
#else
                    error = Error::Parse;
                    errorMsg = errorMessage;
                    return false;
#endif
                }

                return true;
            }

            template <typename It>
            bool ParseShort(It &it, It end)
            {
                const auto &chunk = *it;
                const auto argchunk = chunk.substr(shortprefix.size());
                for (auto argit = std::begin(argchunk); argit != std::end(argchunk); ++argit)
                {
                    const auto arg = *argit;

                    if (auto flag = Match(arg))
                    {
                        const std::string value(argit + 1, std::end(argchunk));
                        std::vector<std::string> values;
                        const std::string errorMessage = ParseArgsValues(*flag, std::string(1, arg), it, end,
                                                                         allowSeparateShortValue, allowJoinedShortValue,
                                                                         !value.empty(), value, !value.empty(), values);

                        if (!errorMessage.empty())
                        {
#ifndef ARGS_NOEXCEPT
                            throw ParseError(errorMessage);
#else
                            error = Error::Parse;
                            errorMsg = errorMessage;
                            return false;
#endif
                        }

                        if (!readCompletion)
                        {
                            flag->ParseValue(values);
                        }

                        if (flag->KickOut())
                        {
                            ++it;
                            return false;
                        }

                        if (!values.empty())
                        {
                            break;
                        }
                    } else
                    {
                        const std::string errorMessage("Flag could not be matched: '" + std::string(1, arg) + "'");
#ifndef ARGS_NOEXCEPT
                        throw ParseError(errorMessage);
#else
                        error = Error::Parse;
                        errorMsg = errorMessage;
                        return false;
#endif
                    }
                }

                return true;
            }

            bool AddCompletionReply(const std::string &cur, const std::string &choice)
            {
                if (cur.empty() || choice.find(cur) == 0)
                {
                    if (completion->syntax == "bash" && ParseOption(choice) == OptionType::LongFlag && choice.find(longseparator) != std::string::npos)
                    {
                        completion->reply.push_back(choice.substr(choice.find(longseparator) + 1));
                    } else
                    {
                        completion->reply.push_back(choice);
                    }
                    return true;
                }

                return false;
            }

            template <typename It>
            bool Complete(It it, It end)
            {
                auto nextIt = it;
                if (!readCompletion || (++nextIt != end))
                {
                    return false;
                }

                const auto &chunk = *it;
                auto pos = GetNextPositional();
                std::vector<Command *> commands = GetCommands();
                const auto optionType = ParseOption(chunk, true);

                if (!commands.empty() && (chunk.empty() || optionType == OptionType::Positional))
                {
                    for (auto &cmd : commands)
                    {
                        if ((cmd->GetOptions() & Options::HiddenFromCompletion) == Options::None)
                        {
                            AddCompletionReply(chunk, cmd->Name());
                        }
                    }
                } else
                {
                    bool hasPositionalCompletion = true;

                    if (!commands.empty())
                    {
                        for (auto &cmd : commands)
                        {
                            if ((cmd->GetOptions() & Options::HiddenFromCompletion) == Options::None)
                            {
                                AddCompletionReply(chunk, cmd->Name());
                            }
                        }
                    } else if (pos)
                    {
                        if ((pos->GetOptions() & Options::HiddenFromCompletion) == Options::None)
                        {
                            auto choices = pos->HelpChoices(helpParams);
                            hasPositionalCompletion = !choices.empty() || optionType != OptionType::Positional;
                            for (auto &choice : choices)
                            {
                                AddCompletionReply(chunk, choice);
                            }
                        }
                    }

                    if (hasPositionalCompletion)
                    {
                        auto flags = GetAllFlags();
                        for (auto flag : flags)
                        {
                            if ((flag->GetOptions() & Options::HiddenFromCompletion) != Options::None)
                            {
                                continue;
                            }

                            auto &matcher = flag->GetMatcher();
                            if (!AddCompletionReply(chunk, matcher.GetShortOrAny().str(shortprefix, longprefix)))
                            {
                                for (auto &flagName : matcher.GetFlagStrings())
                                {
                                    if (AddCompletionReply(chunk, flagName.str(shortprefix, longprefix)))
                                    {
                                        break;
                                    }
                                }
                            }
                        }

                        if (optionType == OptionType::LongFlag && allowJoinedLongValue)
                        {
                            const auto separator = longseparator.empty() ? chunk.npos : chunk.find(longseparator);
                            if (separator != chunk.npos)
                            {
                                std::string arg(chunk, 0, separator);
                                if (auto flag = this->Match(arg.substr(longprefix.size())))
                                {
                                    for (auto &choice : flag->HelpChoices(helpParams))
                                    {
                                        AddCompletionReply(chunk, arg + longseparator + choice);
                                    }
                                }
                            }
                        } else if (optionType == OptionType::ShortFlag && allowJoinedShortValue)
                        {
                            if (chunk.size() > shortprefix.size() + 1)
                            {
                                auto arg = chunk.at(shortprefix.size());
                                if (auto flag = this->Match(arg))
                                {
                                    for (auto &choice : flag->HelpChoices(helpParams))
                                    {
                                        AddCompletionReply(chunk, shortprefix + arg + choice);
                                    }
                                }
                            }
                        }
                    }
                }

#ifndef ARGS_NOEXCEPT
                throw Completion(completion->Get());
#else
                return true;
#endif
            }

            template <typename It>
            It Parse(It begin, It end)
            {
                bool terminated = false;
                std::vector<Command *> commands = GetCommands();

                for (auto it = begin; it != end; ++it)
                {
                    if (Complete(it, end))
                    {
                        return end;
                    }

                    const auto &chunk = *it;

                    if (!terminated && chunk == terminator)
                    {
                        terminated = true;
                    } else if (!terminated && ParseOption(chunk) == OptionType::LongFlag)
                    {
                        if (!ParseLong(it, end))
                        {
                            return it;
                        }
                    } else if (!terminated && ParseOption(chunk) == OptionType::ShortFlag)
                    {
                        if (!ParseShort(it, end))
                        {
                            return it;
                        }
                    } else if (!terminated && !commands.empty())
                    {
                        auto itCommand = std::find_if(commands.begin(), commands.end(), [&chunk](Command *c) { return c->Name() == chunk; });
                        if (itCommand == commands.end())
                        {
                            const std::string errorMessage("Unknown command: " + chunk);
#ifndef ARGS_NOEXCEPT
                            throw ParseError(errorMessage);
#else
                            error = Error::Parse;
                            errorMsg = errorMessage;
                            return it;
#endif
                        }

                        SelectCommand(*itCommand);

                        if (const auto &coroutine = GetCoroutine())
                        {
                            ++it;
                            RaiiSubparser coro(*this, std::vector<std::string>(it, end));
                            coroutine(coro.Parser());
#ifdef ARGS_NOEXCEPT
                            error = GetError();
                            if (error != Error::None)
                            {
                                return end;
                            }

                            if (!coro.Parser().IsParsed())
                            {
                                error = Error::Usage;
                                return end;
                            }
#else
                            if (!coro.Parser().IsParsed())
                            {
                                throw UsageError("Subparser::Parse was not called");
                            }
#endif

                            break;
                        }

                        commands = GetCommands();
                    } else
                    {
                        auto pos = GetNextPositional();
                        if (pos)
                        {
                            pos->ParseValue(chunk);

                            if (pos->KickOut())
                            {
                                return ++it;
                            }
                        } else
                        {
                            const std::string errorMessage("Passed in argument, but no positional arguments were ready to receive it: " + chunk);
#ifndef ARGS_NOEXCEPT
                            throw ParseError(errorMessage);
#else
                            error = Error::Parse;
                            errorMsg = errorMessage;
                            return it;
#endif
                        }
                    }

                    if (!readCompletion && completion != nullptr && completion->Matched())
                    {
#ifdef ARGS_NOEXCEPT
                        error = Error::Completion;
#endif
                        readCompletion = true;
                        ++it;
                        const auto argsLeft = static_cast<size_t>(std::distance(it, end));
                        if (completion->cword == 0 || argsLeft <= 1 || completion->cword >= argsLeft)
                        {
#ifndef ARGS_NOEXCEPT
                            throw Completion("");
#endif
                        }

                        std::vector<std::string> curArgs(++it, end);
                        curArgs.resize(completion->cword);

                        if (completion->syntax == "bash")
                        {
                            for (size_t idx = 0; idx < curArgs.size(); )
                            {
                                if (idx > 0 && curArgs[idx] == "=")
                                {
                                    curArgs[idx - 1] += "=";
                                    const auto signedIdx = static_cast<std::ptrdiff_t>(idx);
                                    if (idx + 1 < curArgs.size())
                                    {
                                        curArgs[idx - 1] += curArgs[idx + 1];
                                        curArgs.erase(curArgs.begin() + signedIdx, curArgs.begin() + signedIdx + 2);
                                    } else
                                    {
                                        curArgs.erase(curArgs.begin() + signedIdx);
                                    }
                                } else
                                {
                                    ++idx;
                                }
                            }

                        }
#ifndef ARGS_NOEXCEPT
                        try
                        {
                            Parse(curArgs.begin(), curArgs.end());
                            throw Completion("");
                        }
                        catch (Completion &)
                        {
                            throw;
                        }
                        catch (args::Error&)
                        {
                            throw Completion("");
                        }
#else
                        return Parse(curArgs.begin(), curArgs.end());
#endif
                    }
                }

                Validate(shortprefix, longprefix);
                return end;
            }

        public:
            HelpParams helpParams;

            ArgumentParser(const std::string &description_, const std::string &epilog_ = std::string())
            {
                Description(description_);
                Epilog(epilog_);
                LongPrefix("--");
                ShortPrefix("-");
                LongSeparator("=");
                Terminator("--");
                SetArgumentSeparations(true, true, true, true);
                matched = true;
            }

            void AddCompletion(CompletionFlag &completionFlag)
            {
                completion = &completionFlag;
                Add(completionFlag);
            }

            const std::string &Prog() const
            { return helpParams.programName; }
            void Prog(const std::string &prog_)
            { this->helpParams.programName = prog_; }

            const std::string &LongPrefix() const
            { return longprefix; }
            void LongPrefix(const std::string &longprefix_)
            {
                this->longprefix = longprefix_;
                this->helpParams.longPrefix = longprefix_;
            }

            const std::string &ShortPrefix() const
            { return shortprefix; }
            void ShortPrefix(const std::string &shortprefix_)
            {
                this->shortprefix = shortprefix_;
                this->helpParams.shortPrefix = shortprefix_;
            }

            const std::string &LongSeparator() const
            { return longseparator; }
            void LongSeparator(const std::string &longseparator_)
            {
                if (longseparator_.empty())
                {
                    const std::string errorMessage("longseparator can not be set to empty");
#ifdef ARGS_NOEXCEPT
                    error = Error::Usage;
                    errorMsg = errorMessage;
#else
                    throw UsageError(errorMessage);
#endif
                } else
                {
                    this->longseparator = longseparator_;
                    this->helpParams.longSeparator = allowJoinedLongValue ? longseparator_ : " ";
                }
            }

            const std::string &Terminator() const
            { return terminator; }
            void Terminator(const std::string &terminator_)
            { this->terminator = terminator_; }

            void GetArgumentSeparations(
                bool &allowJoinedShortValue_,
                bool &allowJoinedLongValue_,
                bool &allowSeparateShortValue_,
                bool &allowSeparateLongValue_) const
            {
                allowJoinedShortValue_ = this->allowJoinedShortValue;
                allowJoinedLongValue_ = this->allowJoinedLongValue;
                allowSeparateShortValue_ = this->allowSeparateShortValue;
                allowSeparateLongValue_ = this->allowSeparateLongValue;
            }

            void SetArgumentSeparations(
                const bool allowJoinedShortValue_,
                const bool allowJoinedLongValue_,
                const bool allowSeparateShortValue_,
                const bool allowSeparateLongValue_)
            {
                this->allowJoinedShortValue = allowJoinedShortValue_;
                this->allowJoinedLongValue = allowJoinedLongValue_;
                this->allowSeparateShortValue = allowSeparateShortValue_;
                this->allowSeparateLongValue = allowSeparateLongValue_;

                this->helpParams.longSeparator = allowJoinedLongValue ? longseparator : " ";
                this->helpParams.shortSeparator = allowJoinedShortValue ? "" : " ";
            }

            void Help(std::ostream &help_) const
            {
                auto &command = SelectedCommand();
                const auto &commandDescription = command.Description().empty() ? command.Help() : command.Description();
                const auto description_text = Wrap(commandDescription, helpParams.width - helpParams.descriptionindent);
                const auto epilog_text = Wrap(command.Epilog(), helpParams.width - helpParams.descriptionindent);

                const bool hasoptions = command.HasFlag();
                const bool hasarguments = command.HasPositional();

                std::vector<std::string> prognameline;
                prognameline.push_back(helpParams.usageString);
                prognameline.push_back(Prog());
                auto commandProgLine = command.GetProgramLine(helpParams);
                prognameline.insert(prognameline.end(), commandProgLine.begin(), commandProgLine.end());

                const auto proglines = Wrap(prognameline.begin(), prognameline.end(),
                                            helpParams.width - (helpParams.progindent + helpParams.progtailindent),
                                            helpParams.width - helpParams.progindent);
                auto progit = std::begin(proglines);
                if (progit != std::end(proglines))
                {
                    help_ << std::string(helpParams.progindent, ' ') << *progit << '\n';
                    ++progit;
                }
                for (; progit != std::end(proglines); ++progit)
                {
                    help_ << std::string(helpParams.progtailindent, ' ') << *progit << '\n';
                }

                help_ << '\n';

                if (!description_text.empty())
                {
                    for (const auto &line: description_text)
                    {
                        help_ << std::string(helpParams.descriptionindent, ' ') << line << "\n";
                    }
                    help_ << "\n";
                }

                bool lastDescriptionIsNewline = false;

                if (!helpParams.optionsString.empty())
                {
                    help_ << std::string(helpParams.progindent, ' ') << helpParams.optionsString << "\n\n";
                }

                for (const auto &desc: command.GetDescription(helpParams, 0))
                {
                    lastDescriptionIsNewline = std::get<0>(desc).empty() && std::get<1>(desc).empty();
                    const auto groupindent = std::get<2>(desc) * helpParams.eachgroupindent;
                    const auto flags = Wrap(std::get<0>(desc), helpParams.width - (helpParams.flagindent + helpParams.helpindent + helpParams.gutter));
                    const auto info = Wrap(std::get<1>(desc), helpParams.width - (helpParams.helpindent + groupindent));

                    std::string::size_type flagssize = 0;
                    for (auto flagsit = std::begin(flags); flagsit != std::end(flags); ++flagsit)
                    {
                        if (flagsit != std::begin(flags))
                        {
                            help_ << '\n';
                        }
                        help_ << std::string(groupindent + helpParams.flagindent, ' ') << *flagsit;
                        flagssize = Glyphs(*flagsit);
                    }

                    auto infoit = std::begin(info);
                    if ((helpParams.flagindent + flagssize + helpParams.gutter) > helpParams.helpindent || infoit == std::end(info) || helpParams.addNewlineBeforeDescription)
                    {
                        help_ << '\n';
                    } else
                    {
                        help_ << std::string(helpParams.helpindent - (helpParams.flagindent + flagssize), ' ') << *infoit << '\n';
                        ++infoit;
                    }
                    for (; infoit != std::end(info); ++infoit)
                    {
                        help_ << std::string(groupindent + helpParams.helpindent, ' ') << *infoit << '\n';
                    }
                }
                if (hasoptions && hasarguments && helpParams.showTerminator)
                {
                    lastDescriptionIsNewline = false;
                    for (const auto &item: Wrap(std::string("\"") + terminator + "\" can be used to terminate flag options and force all following arguments to be treated as positional options", helpParams.width - helpParams.flagindent))
                    {
                        help_ << std::string(helpParams.flagindent, ' ') << item << '\n';
                    }
                }

                if (!lastDescriptionIsNewline)
                {
                    help_ << "\n";
                }

                for (const auto &line: epilog_text)
                {
                    help_ << std::string(helpParams.descriptionindent, ' ') << line << "\n";
                }
            }

            std::string Help() const
            {
                std::ostringstream help_;
                Help(help_);
                return help_.str();
            }

            virtual void Reset() noexcept override
            {
                Command::Reset();
                matched = true;
                readCompletion = false;
            }

            template <typename It>
            It ParseArgs(It begin, It end)
            {
                Reset();
#ifdef ARGS_NOEXCEPT
                error = GetError();
                if (error != Error::None)
                {
                    return end;
                }
#endif
                return Parse(begin, end);
            }

            template <typename T>
            auto ParseArgs(const T &args) -> decltype(std::begin(args))
            {
                return ParseArgs(std::begin(args), std::end(args));
            }

            bool ParseCLI(const int argc, const char * const * argv)
            {
                if (Prog().empty())
                {
                    Prog(argv[0]);
                }
                const std::vector<std::string> args(argv + 1, argv + argc);
                return ParseArgs(args) == std::end(args);
            }

            template <typename T>
            bool ParseCLI(const T &args)
            {
                return ParseArgs(args) == std::end(args);
            }
    };

    inline Command::RaiiSubparser::RaiiSubparser(ArgumentParser &parser_, std::vector<std::string> args_)
        : command(parser_.SelectedCommand()), parser(std::move(args_), parser_, command, parser_.helpParams), oldSubparser(command.subparser)
    {
        command.subparser = &parser;
    }

    inline Command::RaiiSubparser::RaiiSubparser(const Command &command_, const HelpParams &params_): command(command_), parser(command, params_), oldSubparser(command.subparser)
    {
        command.subparser = &parser;
    }

    inline void Subparser::Parse()
    {
        isParsed = true;
        Reset();
        command.subparserDescription = GetDescription(helpParams, 0);
        command.subparserHasFlag = HasFlag();
        command.subparserHasPositional = HasPositional();
        command.subparserHasCommand = HasCommand();
        command.subparserProgramLine = GetProgramLine(helpParams);
        if (parser == nullptr)
        {
#ifndef ARGS_NOEXCEPT
            throw args::SubparserError();
#else
            error = Error::Subparser;
            return;
#endif
        }

        auto it = parser->Parse(args.begin(), args.end());
        command.Validate(parser->ShortPrefix(), parser->LongPrefix());
        kicked.assign(it, args.end());

#ifdef ARGS_NOEXCEPT
        command.subparserError = GetError();
#endif
    }

    inline std::ostream &operator<<(std::ostream &os, const ArgumentParser &parser)
    {
        parser.Help(os);
        return os;
    }

    class Flag : public FlagBase
    {
        public:
            Flag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, Options options_): FlagBase(name_, help_, std::move(matcher_), options_)
            {
                group_.Add(*this);
            }

            Flag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, const bool extraError_ = false): Flag(group_, name_, help_, std::move(matcher_), extraError_ ? Options::Single : Options::None)
            {
            }

            virtual ~Flag() {}

            bool Get() const
            {
                return Matched();
            }

            virtual Nargs NumberOfArguments() const noexcept override
            {
                return 0;
            }

            virtual void ParseValue(const std::vector<std::string>&) override
            {
            }
    };

    class HelpFlag : public Flag
    {
        public:
            HelpFlag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, Options options_ = {}): Flag(group_, name_, help_, std::move(matcher_), options_) {}

            virtual ~HelpFlag() {}

            virtual void ParseValue(const std::vector<std::string> &)
            {
#ifdef ARGS_NOEXCEPT
                    error = Error::Help;
                    errorMsg = Name();
#else
                    throw Help(Name());
#endif
            }

            bool Get() const noexcept
            {
                return Matched();
            }
    };

    class CounterFlag : public Flag
    {
        private:
            const int startcount;
            int count;

        public:
            CounterFlag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, const int startcount_ = 0, Options options_ = {}):
                Flag(group_, name_, help_, std::move(matcher_), options_), startcount(startcount_), count(startcount_) {}

            virtual ~CounterFlag() {}

            virtual FlagBase *Match(const EitherFlag &arg) override
            {
                auto me = FlagBase::Match(arg);
                if (me)
                {
                    ++count;
                }
                return me;
            }

            int &Get() noexcept
            {
                return count;
            }

            int &operator *() noexcept {
                return count;
            }

            const int &operator *() const noexcept {
                return count;
            }

            virtual void Reset() noexcept override
            {
                FlagBase::Reset();
                count = startcount;
            }
    };

    class ActionFlag : public FlagBase
    {
        private:
            std::function<void(const std::vector<std::string> &)> action;
            Nargs nargs;

        public:
            ActionFlag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, Nargs nargs_, std::function<void(const std::vector<std::string> &)> action_, Options options_ = {}):
                FlagBase(name_, help_, std::move(matcher_), options_), action(std::move(action_)), nargs(nargs_)
            {
                group_.Add(*this);
            }

            ActionFlag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, std::function<void(const std::string &)> action_, Options options_ = {}):
                FlagBase(name_, help_, std::move(matcher_), options_), nargs(1)
            {
                group_.Add(*this);
                action = [action_](const std::vector<std::string> &a) { return action_(a.at(0)); };
            }

            ActionFlag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, std::function<void()> action_, Options options_ = {}):
                FlagBase(name_, help_, std::move(matcher_), options_), nargs(0)
            {
                group_.Add(*this);
                action = [action_](const std::vector<std::string> &) { return action_(); };
            }

            virtual Nargs NumberOfArguments() const noexcept override
            { return nargs; }

            virtual void ParseValue(const std::vector<std::string> &value) override
            { action(value); }
    };

    struct ValueReader
    {
        template <typename T>
        typename std::enable_if<!std::is_assignable<T, std::string>::value, bool>::type
        operator ()(const std::string &name, const std::string &value, T &destination)
        {
            std::istringstream ss(value);
            bool failed = !(ss >> destination);

            if (!failed)
            {
                ss >> std::ws;
            }

            if (ss.rdbuf()->in_avail() > 0 || failed)
            {
#ifdef ARGS_NOEXCEPT
                (void)name;
                return false;
#else
                std::ostringstream problem;
                problem << "Argument '" << name << "' received invalid value type '" << value << "'";
                throw ParseError(problem.str());
#endif
            }
            return true;
        }

        template <typename T>
        typename std::enable_if<std::is_assignable<T, std::string>::value, bool>::type
        operator()(const std::string &, const std::string &value, T &destination)
        {
            destination = value;
            return true;
        }
    };

    template <
        typename T,
        typename Reader = ValueReader>
    class ValueFlag : public ValueFlagBase
    {
        protected:
            T value;
            T defaultValue;

            virtual std::string GetDefaultString(const HelpParams&) const override
            {
                return detail::ToString(defaultValue);
            }

        private:
            Reader reader;

        public:

            ValueFlag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, const T &defaultValue_, Options options_): ValueFlagBase(name_, help_, std::move(matcher_), options_), value(defaultValue_), defaultValue(defaultValue_)
            {
                group_.Add(*this);
            }

            ValueFlag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, const T &defaultValue_ = T(), const bool extraError_ = false): ValueFlag(group_, name_, help_, std::move(matcher_), defaultValue_, extraError_ ? Options::Single : Options::None)
            {
            }

            ValueFlag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, Options options_): ValueFlag(group_, name_, help_, std::move(matcher_), T(), options_)
            {
            }

            virtual ~ValueFlag() {}

            virtual void ParseValue(const std::vector<std::string> &values_) override
            {
                const std::string &value_ = values_.at(0);

#ifdef ARGS_NOEXCEPT
                if (!reader(name, value_, this->value))
                {
                    error = Error::Parse;
                }
#else
                reader(name, value_, this->value);
#endif
            }

            virtual void Reset() noexcept override
            {
                ValueFlagBase::Reset();
                value = defaultValue;
            }

            T &Get() noexcept
            {
                return value;
            }

            T &operator *() noexcept
            {
                return value;
            }

            const T &operator *() const noexcept
            {
                return value;
            }

            T *operator ->() noexcept
            {
                return &value;
            }

            const T *operator ->() const noexcept
            {
                return &value;
            }

            const T &GetDefault() noexcept
            {
                return defaultValue;
            }
    };

    template <
        typename T,
        typename Reader = ValueReader>
    class ImplicitValueFlag : public ValueFlag<T, Reader>
    {
        protected:
            T implicitValue;

        public:

            ImplicitValueFlag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, const T &implicitValue_, const T &defaultValue_ = T(), Options options_ = {})
                : ValueFlag<T, Reader>(group_, name_, help_, std::move(matcher_), defaultValue_, options_), implicitValue(implicitValue_)
            {
            }

            ImplicitValueFlag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, const T &defaultValue_ = T(), Options options_ = {})
                : ValueFlag<T, Reader>(group_, name_, help_, std::move(matcher_), defaultValue_, options_), implicitValue(defaultValue_)
            {
            }

            ImplicitValueFlag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, Options options_)
                : ValueFlag<T, Reader>(group_, name_, help_, std::move(matcher_), {}, options_), implicitValue()
            {
            }

            virtual ~ImplicitValueFlag() {}

            virtual Nargs NumberOfArguments() const noexcept override
            {
                return {0, 1};
            }

            virtual void ParseValue(const std::vector<std::string> &value_) override
            {
                if (value_.empty())
                {
                    this->value = implicitValue;
                } else
                {
                    ValueFlag<T, Reader>::ParseValue(value_);
                }
            }
    };

    template <
        typename T,
        template <typename...> class List = detail::vector,
        typename Reader = ValueReader>
    class NargsValueFlag : public FlagBase
    {
        protected:

            List<T> values;
            const List<T> defaultValues;
            Nargs nargs;
            Reader reader;

        public:

            typedef List<T> Container;
            typedef T value_type;
            typedef typename Container::allocator_type allocator_type;
            typedef typename Container::pointer pointer;
            typedef typename Container::const_pointer const_pointer;
            typedef T& reference;
            typedef const T& const_reference;
            typedef typename Container::size_type size_type;
            typedef typename Container::difference_type difference_type;
            typedef typename Container::iterator iterator;
            typedef typename Container::const_iterator const_iterator;
            typedef std::reverse_iterator<iterator> reverse_iterator;
            typedef std::reverse_iterator<const_iterator> const_reverse_iterator;

            NargsValueFlag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, Nargs nargs_, const List<T> &defaultValues_ = {}, Options options_ = {})
                : FlagBase(name_, help_, std::move(matcher_), options_), values(defaultValues_), defaultValues(defaultValues_),nargs(nargs_)
            {
                group_.Add(*this);
            }

            virtual ~NargsValueFlag() {}

            virtual Nargs NumberOfArguments() const noexcept override
            {
                return nargs;
            }

            virtual void ParseValue(const std::vector<std::string> &values_) override
            {
                values.clear();

                for (const std::string &value : values_)
                {
                    T v;
#ifdef ARGS_NOEXCEPT
                    if (!reader(name, value, v))
                    {
                        error = Error::Parse;
                    }
#else
                    reader(name, value, v);
#endif
                    values.insert(std::end(values), v);
                }
            }

            List<T> &Get() noexcept
            {
                return values;
            }

            List<T> &operator *() noexcept
            {
                return values;
            }

            const List<T> &operator *() const noexcept
            {
                return values;
            }

            List<T> *operator ->() noexcept
            {
                return &values;
            }

            const List<T> *operator ->() const noexcept
            {
                return &values;
            }

            iterator begin() noexcept
            {
                return values.begin();
            }

            const_iterator begin() const noexcept
            {
                return values.begin();
            }

            const_iterator cbegin() const noexcept
            {
                return values.cbegin();
            }

            iterator end() noexcept
            {
                return values.end();
            }

            const_iterator end() const noexcept
            {
                return values.end();
            }

            const_iterator cend() const noexcept
            {
                return values.cend();
            }

            virtual void Reset() noexcept override
            {
                FlagBase::Reset();
                values = defaultValues;
            }

            virtual FlagBase *Match(const EitherFlag &arg) override
            {
                const bool wasMatched = Matched();
                auto me = FlagBase::Match(arg);
                if (me && !wasMatched)
                {
                    values.clear();
                }
                return me;
            }
    };

    template <
        typename T,
        template <typename...> class List = detail::vector,
        typename Reader = ValueReader>
    class ValueFlagList : public ValueFlagBase
    {
        private:
            using Container = List<T>;
            Container values;
            const Container defaultValues;
            Reader reader;

        public:

            typedef T value_type;
            typedef typename Container::allocator_type allocator_type;
            typedef typename Container::pointer pointer;
            typedef typename Container::const_pointer const_pointer;
            typedef T& reference;
            typedef const T& const_reference;
            typedef typename Container::size_type size_type;
            typedef typename Container::difference_type difference_type;
            typedef typename Container::iterator iterator;
            typedef typename Container::const_iterator const_iterator;
            typedef std::reverse_iterator<iterator> reverse_iterator;
            typedef std::reverse_iterator<const_iterator> const_reverse_iterator;

            ValueFlagList(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, const Container &defaultValues_ = Container(), Options options_ = {}):
                ValueFlagBase(name_, help_, std::move(matcher_), options_), values(defaultValues_), defaultValues(defaultValues_)
            {
                group_.Add(*this);
            }

            virtual ~ValueFlagList() {}

            virtual void ParseValue(const std::vector<std::string> &values_) override
            {
                const std::string &value_ = values_.at(0);

                T v;
#ifdef ARGS_NOEXCEPT
                if (!reader(name, value_, v))
                {
                    error = Error::Parse;
                }
#else
                reader(name, value_, v);
#endif
                values.insert(std::end(values), v);
            }

            Container &Get() noexcept
            {
                return values;
            }

            Container &operator *() noexcept
            {
                return values;
            }

            const Container &operator *() const noexcept
            {
                return values;
            }

            Container *operator ->() noexcept
            {
                return &values;
            }

            const Container *operator ->() const noexcept
            {
                return &values;
            }

            virtual std::string Name() const override
            {
                return name + std::string("...");
            }

            virtual void Reset() noexcept override
            {
                ValueFlagBase::Reset();
                values = defaultValues;
            }

            virtual FlagBase *Match(const EitherFlag &arg) override
            {
                const bool wasMatched = Matched();
                auto me = FlagBase::Match(arg);
                if (me && !wasMatched)
                {
                    values.clear();
                }
                return me;
            }

            iterator begin() noexcept
            {
                return values.begin();
            }

            const_iterator begin() const noexcept
            {
                return values.begin();
            }

            const_iterator cbegin() const noexcept
            {
                return values.cbegin();
            }

            iterator end() noexcept
            {
                return values.end();
            }

            const_iterator end() const noexcept
            {
                return values.end();
            }

            const_iterator cend() const noexcept
            {
                return values.cend();
            }
    };

    template <
        typename K,
        typename T,
        typename Reader = ValueReader,
        template <typename...> class Map = detail::unordered_map>
    class MapFlag : public ValueFlagBase
    {
        private:
            const Map<K, T> map;
            T value;
            const T defaultValue;
            Reader reader;

        protected:
            virtual std::vector<std::string> GetChoicesStrings(const HelpParams &) const override
            {
                return detail::MapKeysToStrings(map);
            }

        public:

            MapFlag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, const Map<K, T> &map_, const T &defaultValue_, Options options_): ValueFlagBase(name_, help_, std::move(matcher_), options_), map(map_), value(defaultValue_), defaultValue(defaultValue_)
            {
                group_.Add(*this);
            }

            MapFlag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, const Map<K, T> &map_, const T &defaultValue_ = T(), const bool extraError_ = false): MapFlag(group_, name_, help_, std::move(matcher_), map_, defaultValue_, extraError_ ? Options::Single : Options::None)
            {
            }

            MapFlag(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, const Map<K, T> &map_, Options options_): MapFlag(group_, name_, help_, std::move(matcher_), map_, T(), options_)
            {
            }

            virtual ~MapFlag() {}

            virtual void ParseValue(const std::vector<std::string> &values_) override
            {
                const std::string &value_ = values_.at(0);

                K key;
#ifdef ARGS_NOEXCEPT
                if (!reader(name, value_, key))
                {
                    error = Error::Parse;
                }
#else
                reader(name, value_, key);
#endif
                auto it = map.find(key);
                if (it == std::end(map))
                {
                    std::ostringstream problem;
                    problem << "Could not find key '" << key << "' in map for arg '" << name << "'";
#ifdef ARGS_NOEXCEPT
                    error = Error::Map;
                    errorMsg = problem.str();
#else
                    throw MapError(problem.str());
#endif
                } else
                {
                    this->value = it->second;
                }
            }

            T &Get() noexcept
            {
                return value;
            }

            T &operator *() noexcept
            {
                return value;
            }

            const T &operator *() const noexcept
            {
                return value;
            }

            T *operator ->() noexcept
            {
                return &value;
            }

            const T *operator ->() const noexcept
            {
                return &value;
            }

            virtual void Reset() noexcept override
            {
                ValueFlagBase::Reset();
                value = defaultValue;
            }
    };

    template <
        typename K,
        typename T,
        template <typename...> class List = detail::vector,
        typename Reader = ValueReader,
        template <typename...> class Map = detail::unordered_map>
    class MapFlagList : public ValueFlagBase
    {
        private:
            using Container = List<T>;
            const Map<K, T> map;
            Container values;
            const Container defaultValues;
            Reader reader;

        protected:
            virtual std::vector<std::string> GetChoicesStrings(const HelpParams &) const override
            {
                return detail::MapKeysToStrings(map);
            }

        public:
            typedef T value_type;
            typedef typename Container::allocator_type allocator_type;
            typedef typename Container::pointer pointer;
            typedef typename Container::const_pointer const_pointer;
            typedef T& reference;
            typedef const T& const_reference;
            typedef typename Container::size_type size_type;
            typedef typename Container::difference_type difference_type;
            typedef typename Container::iterator iterator;
            typedef typename Container::const_iterator const_iterator;
            typedef std::reverse_iterator<iterator> reverse_iterator;
            typedef std::reverse_iterator<const_iterator> const_reverse_iterator;

            MapFlagList(Group &group_, const std::string &name_, const std::string &help_, Matcher &&matcher_, const Map<K, T> &map_, const Container &defaultValues_ = Container()): ValueFlagBase(name_, help_, std::move(matcher_)), map(map_), values(defaultValues_), defaultValues(defaultValues_)
            {
                group_.Add(*this);
            }

            virtual ~MapFlagList() {}

            virtual void ParseValue(const std::vector<std::string> &values_) override
            {
                const std::string &value = values_.at(0);

                K key;
#ifdef ARGS_NOEXCEPT
                if (!reader(name, value, key))
                {
                    error = Error::Parse;
                }
#else
                reader(name, value, key);
#endif
                auto it = map.find(key);
                if (it == std::end(map))
                {
                    std::ostringstream problem;
                    problem << "Could not find key '" << key << "' in map for arg '" << name << "'";
#ifdef ARGS_NOEXCEPT
                    error = Error::Map;
                    errorMsg = problem.str();
#else
                    throw MapError(problem.str());
#endif
                } else
                {
                    this->values.emplace_back(it->second);
                }
            }

            Container &Get() noexcept
            {
                return values;
            }

            Container &operator *() noexcept
            {
                return values;
            }

            const Container &operator *() const noexcept
            {
                return values;
            }

            Container *operator ->() noexcept
            {
                return &values;
            }

            const Container *operator ->() const noexcept
            {
                return &values;
            }

            virtual std::string Name() const override
            {
                return name + std::string("...");
            }

            virtual void Reset() noexcept override
            {
                ValueFlagBase::Reset();
                values = defaultValues;
            }

            virtual FlagBase *Match(const EitherFlag &arg) override
            {
                const bool wasMatched = Matched();
                auto me = FlagBase::Match(arg);
                if (me && !wasMatched)
                {
                    values.clear();
                }
                return me;
            }

            iterator begin() noexcept
            {
                return values.begin();
            }

            const_iterator begin() const noexcept
            {
                return values.begin();
            }

            const_iterator cbegin() const noexcept
            {
                return values.cbegin();
            }

            iterator end() noexcept
            {
                return values.end();
            }

            const_iterator end() const noexcept
            {
                return values.end();
            }

            const_iterator cend() const noexcept
            {
                return values.cend();
            }
    };

    template <
        typename T,
        typename Reader = ValueReader>
    class Positional : public PositionalBase
    {
        private:
            T value;
            const T defaultValue;
            Reader reader;
        public:
            Positional(Group &group_, const std::string &name_, const std::string &help_, const T &defaultValue_ = T(), Options options_ = {}): PositionalBase(name_, help_, options_), value(defaultValue_), defaultValue(defaultValue_)
            {
                group_.Add(*this);
            }

            Positional(Group &group_, const std::string &name_, const std::string &help_, Options options_): Positional(group_, name_, help_, T(), options_)
            {
            }

            virtual ~Positional() {}

            virtual void ParseValue(const std::string &value_) override
            {
#ifdef ARGS_NOEXCEPT
                if (!reader(name, value_, this->value))
                {
                    error = Error::Parse;
                }
#else
                reader(name, value_, this->value);
#endif
                ready = false;
                matched = true;
            }

            T &Get() noexcept
            {
                return value;
            }

            T &operator *() noexcept
            {
                return value;
            }

            const T &operator *() const noexcept
            {
                return value;
            }

            T *operator ->() noexcept
            {
                return &value;
            }

            const T *operator ->() const noexcept
            {
                return &value;
            }

            virtual void Reset() noexcept override
            {
                PositionalBase::Reset();
                value = defaultValue;
            }
    };

    template <
        typename T,
        template <typename...> class List = detail::vector,
        typename Reader = ValueReader>
    class PositionalList : public PositionalBase
    {
        private:
            using Container = List<T>;
            Container values;
            const Container defaultValues;
            Reader reader;

        public:
            typedef T value_type;
            typedef typename Container::allocator_type allocator_type;
            typedef typename Container::pointer pointer;
            typedef typename Container::const_pointer const_pointer;
            typedef T& reference;
            typedef const T& const_reference;
            typedef typename Container::size_type size_type;
            typedef typename Container::difference_type difference_type;
            typedef typename Container::iterator iterator;
            typedef typename Container::const_iterator const_iterator;
            typedef std::reverse_iterator<iterator> reverse_iterator;
            typedef std::reverse_iterator<const_iterator> const_reverse_iterator;

            PositionalList(Group &group_, const std::string &name_, const std::string &help_, const Container &defaultValues_ = Container(), Options options_ = {}): PositionalBase(name_, help_, options_), values(defaultValues_), defaultValues(defaultValues_)
            {
                group_.Add(*this);
            }

            PositionalList(Group &group_, const std::string &name_, const std::string &help_, Options options_): PositionalList(group_, name_, help_, {}, options_)
            {
            }

            virtual ~PositionalList() {}

            virtual void ParseValue(const std::string &value_) override
            {
                T v;
#ifdef ARGS_NOEXCEPT
                if (!reader(name, value_, v))
                {
                    error = Error::Parse;
                }
#else
                reader(name, value_, v);
#endif
                values.insert(std::end(values), v);
                matched = true;
            }

            virtual std::string Name() const override
            {
                return name + std::string("...");
            }

            Container &Get() noexcept
            {
                return values;
            }

            Container &operator *() noexcept
            {
                return values;
            }

            const Container &operator *() const noexcept
            {
                return values;
            }

            Container *operator ->() noexcept
            {
                return &values;
            }

            const Container *operator ->() const noexcept
            {
                return &values;
            }

            virtual void Reset() noexcept override
            {
                PositionalBase::Reset();
                values = defaultValues;
            }

            virtual PositionalBase *GetNextPositional() override
            {
                const bool wasMatched = Matched();
                auto me = PositionalBase::GetNextPositional();
                if (me && !wasMatched)
                {
                    values.clear();
                }
                return me;
            }

            iterator begin() noexcept
            {
                return values.begin();
            }

            const_iterator begin() const noexcept
            {
                return values.begin();
            }

            const_iterator cbegin() const noexcept
            {
                return values.cbegin();
            }

            iterator end() noexcept
            {
                return values.end();
            }

            const_iterator end() const noexcept
            {
                return values.end();
            }

            const_iterator cend() const noexcept
            {
                return values.cend();
            }
    };

    template <
        typename K,
        typename T,
        typename Reader = ValueReader,
        template <typename...> class Map = detail::unordered_map>
    class MapPositional : public PositionalBase
    {
        private:
            const Map<K, T> map;
            T value;
            const T defaultValue;
            Reader reader;

        protected:
            virtual std::vector<std::string> GetChoicesStrings(const HelpParams &) const override
            {
                return detail::MapKeysToStrings(map);
            }

        public:

            MapPositional(Group &group_, const std::string &name_, const std::string &help_, const Map<K, T> &map_, const T &defaultValue_ = T(), Options options_ = {}):
                PositionalBase(name_, help_, options_), map(map_), value(defaultValue_), defaultValue(defaultValue_)
            {
                group_.Add(*this);
            }

            virtual ~MapPositional() {}

            virtual void ParseValue(const std::string &value_) override
            {
                K key;
#ifdef ARGS_NOEXCEPT
                if (!reader(name, value_, key))
                {
                    error = Error::Parse;
                }
#else
                reader(name, value_, key);
#endif
                auto it = map.find(key);
                if (it == std::end(map))
                {
                    std::ostringstream problem;
                    problem << "Could not find key '" << key << "' in map for arg '" << name << "'";
#ifdef ARGS_NOEXCEPT
                    error = Error::Map;
                    errorMsg = problem.str();
#else
                    throw MapError(problem.str());
#endif
                } else
                {
                    this->value = it->second;
                    ready = false;
                    matched = true;
                }
            }

            T &Get() noexcept
            {
                return value;
            }

            T &operator *() noexcept
            {
                return value;
            }

            const T &operator *() const noexcept
            {
                return value;
            }

            T *operator ->() noexcept
            {
                return &value;
            }

            const T *operator ->() const noexcept
            {
                return &value;
            }

            virtual void Reset() noexcept override
            {
                PositionalBase::Reset();
                value = defaultValue;
            }
    };

    template <
        typename K,
        typename T,
        template <typename...> class List = detail::vector,
        typename Reader = ValueReader,
        template <typename...> class Map = detail::unordered_map>
    class MapPositionalList : public PositionalBase
    {
        private:
            using Container = List<T>;

            const Map<K, T> map;
            Container values;
            const Container defaultValues;
            Reader reader;

        protected:
            virtual std::vector<std::string> GetChoicesStrings(const HelpParams &) const override
            {
                return detail::MapKeysToStrings(map);
            }

        public:
            typedef T value_type;
            typedef typename Container::allocator_type allocator_type;
            typedef typename Container::pointer pointer;
            typedef typename Container::const_pointer const_pointer;
            typedef T& reference;
            typedef const T& const_reference;
            typedef typename Container::size_type size_type;
            typedef typename Container::difference_type difference_type;
            typedef typename Container::iterator iterator;
            typedef typename Container::const_iterator const_iterator;
            typedef std::reverse_iterator<iterator> reverse_iterator;
            typedef std::reverse_iterator<const_iterator> const_reverse_iterator;

            MapPositionalList(Group &group_, const std::string &name_, const std::string &help_, const Map<K, T> &map_, const Container &defaultValues_ = Container(), Options options_ = {}):
                PositionalBase(name_, help_, options_), map(map_), values(defaultValues_), defaultValues(defaultValues_)
            {
                group_.Add(*this);
            }

            virtual ~MapPositionalList() {}

            virtual void ParseValue(const std::string &value_) override
            {
                K key;
#ifdef ARGS_NOEXCEPT
                if (!reader(name, value_, key))
                {
                    error = Error::Parse;
                }
#else
                reader(name, value_, key);
#endif
                auto it = map.find(key);
                if (it == std::end(map))
                {
                    std::ostringstream problem;
                    problem << "Could not find key '" << key << "' in map for arg '" << name << "'";
#ifdef ARGS_NOEXCEPT
                    error = Error::Map;
                    errorMsg = problem.str();
#else
                    throw MapError(problem.str());
#endif
                } else
                {
                    this->values.emplace_back(it->second);
                    matched = true;
                }
            }

            Container &Get() noexcept
            {
                return values;
            }

            Container &operator *() noexcept
            {
                return values;
            }

            const Container &operator *() const noexcept
            {
                return values;
            }

            Container *operator ->() noexcept
            {
                return &values;
            }

            const Container *operator ->() const noexcept
            {
                return &values;
            }

            virtual std::string Name() const override
            {
                return name + std::string("...");
            }

            virtual void Reset() noexcept override
            {
                PositionalBase::Reset();
                values = defaultValues;
            }

            virtual PositionalBase *GetNextPositional() override
            {
                const bool wasMatched = Matched();
                auto me = PositionalBase::GetNextPositional();
                if (me && !wasMatched)
                {
                    values.clear();
                }
                return me;
            }

            iterator begin() noexcept
            {
                return values.begin();
            }

            const_iterator begin() const noexcept
            {
                return values.begin();
            }

            const_iterator cbegin() const noexcept
            {
                return values.cbegin();
            }

            iterator end() noexcept
            {
                return values.end();
            }

            const_iterator end() const noexcept
            {
                return values.end();
            }

            const_iterator cend() const noexcept
            {
                return values.cend();
            }
    };
}

#endif
