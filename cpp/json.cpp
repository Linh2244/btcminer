#include "json.h"

#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace {

constexpr int kMaxDepth = 128;

struct Parser {
    const char* p;
    const char* end;
    std::string error;

    void skip_space() {
        while (p < end &&
               (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) {
            ++p;
        }
    }

    bool fail(const std::string& message) {
        if (error.empty()) error = message;
        return false;
    }

    bool parse_value(Json& out, int depth) {
        if (depth > kMaxDepth) return fail("nesting too deep");
        skip_space();
        if (p >= end) return fail("unexpected end of input");
        switch (*p) {
            case '{': return parse_object(out, depth);
            case '[': return parse_array(out, depth);
            case '"': {
                std::string text;
                if (!parse_string(text)) return false;
                out = Json::make_string(std::move(text));
                return true;
            }
            case 't':
                if (end - p >= 4 && std::strncmp(p, "true", 4) == 0) {
                    p += 4;
                    out = Json::make_bool(true);
                    return true;
                }
                return fail("invalid literal");
            case 'f':
                if (end - p >= 5 && std::strncmp(p, "false", 5) == 0) {
                    p += 5;
                    out = Json::make_bool(false);
                    return true;
                }
                return fail("invalid literal");
            case 'n':
                if (end - p >= 4 && std::strncmp(p, "null", 4) == 0) {
                    p += 4;
                    out = Json::make_null();
                    return true;
                }
                return fail("invalid literal");
            default: return parse_number(out);
        }
    }

    bool parse_object(Json& out, int depth) {
        ++p;  // '{'
        out = Json::make_object();
        skip_space();
        if (p < end && *p == '}') { ++p; return true; }
        while (true) {
            skip_space();
            if (p >= end || *p != '"') return fail("expected object key");
            std::string key;
            if (!parse_string(key)) return false;
            skip_space();
            if (p >= end || *p != ':') return fail("expected ':'");
            ++p;
            Json value;
            if (!parse_value(value, depth + 1)) return false;
            out.set(std::move(key), std::move(value));
            skip_space();
            if (p >= end) return fail("unterminated object");
            if (*p == ',') { ++p; continue; }
            if (*p == '}') { ++p; return true; }
            return fail("expected ',' or '}'");
        }
    }

    bool parse_array(Json& out, int depth) {
        ++p;  // '['
        out = Json::make_array();
        skip_space();
        if (p < end && *p == ']') { ++p; return true; }
        while (true) {
            Json value;
            if (!parse_value(value, depth + 1)) return false;
            out.push(std::move(value));
            skip_space();
            if (p >= end) return fail("unterminated array");
            if (*p == ',') { ++p; continue; }
            if (*p == ']') { ++p; return true; }
            return fail("expected ',' or ']'");
        }
    }

    static void append_utf8(std::string& out, unsigned codepoint) {
        if (codepoint < 0x80) {
            out.push_back(char(codepoint));
        } else if (codepoint < 0x800) {
            out.push_back(char(0xc0 | (codepoint >> 6)));
            out.push_back(char(0x80 | (codepoint & 0x3f)));
        } else if (codepoint < 0x10000) {
            out.push_back(char(0xe0 | (codepoint >> 12)));
            out.push_back(char(0x80 | ((codepoint >> 6) & 0x3f)));
            out.push_back(char(0x80 | (codepoint & 0x3f)));
        } else {
            out.push_back(char(0xf0 | (codepoint >> 18)));
            out.push_back(char(0x80 | ((codepoint >> 12) & 0x3f)));
            out.push_back(char(0x80 | ((codepoint >> 6) & 0x3f)));
            out.push_back(char(0x80 | (codepoint & 0x3f)));
        }
    }

    bool parse_hex4(unsigned& value) {
        if (end - p < 4) return fail("truncated \\u escape");
        value = 0;
        for (int i = 0; i < 4; ++i) {
            char c = *p++;
            unsigned digit;
            if (c >= '0' && c <= '9') digit = unsigned(c - '0');
            else if (c >= 'a' && c <= 'f') digit = unsigned(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') digit = unsigned(c - 'A' + 10);
            else return fail("invalid \\u escape");
            value = value * 16 + digit;
        }
        return true;
    }

    bool parse_string(std::string& out) {
        ++p;  // '"'
        out.clear();
        while (p < end) {
            unsigned char c = (unsigned char)*p++;
            if (c == '"') return true;
            if (c != '\\') {
                out.push_back(char(c));
                continue;
            }
            if (p >= end) return fail("truncated escape");
            char esc = *p++;
            switch (esc) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    unsigned code = 0;
                    if (!parse_hex4(code)) return false;
                    if (code >= 0xd800 && code <= 0xdbff &&
                        end - p >= 6 && p[0] == '\\' && p[1] == 'u') {
                        unsigned low = 0;
                        p += 2;
                        if (!parse_hex4(low)) return false;
                        if (low >= 0xdc00 && low <= 0xdfff) {
                            code = 0x10000 + ((code - 0xd800) << 10) +
                                   (low - 0xdc00);
                        } else {
                            append_utf8(out, code);
                            code = low;
                        }
                    }
                    append_utf8(out, code);
                    break;
                }
                default: return fail("unknown escape sequence");
            }
        }
        return fail("unterminated string");
    }

    bool parse_number(Json& out) {
        const char* start = p;
        if (p < end && (*p == '-' || *p == '+')) ++p;
        bool digits = false;
        while (p < end && *p >= '0' && *p <= '9') { ++p; digits = true; }
        bool integer = true;
        if (p < end && *p == '.') {
            integer = false;
            ++p;
            while (p < end && *p >= '0' && *p <= '9') { ++p; digits = true; }
        }
        if (p < end && (*p == 'e' || *p == 'E')) {
            integer = false;
            ++p;
            if (p < end && (*p == '-' || *p == '+')) ++p;
            while (p < end && *p >= '0' && *p <= '9') ++p;
        }
        if (!digits) return fail("invalid number");

        std::string text(start, p);
        if (integer) {
            errno = 0;
            char* stop = nullptr;
            long long value = std::strtoll(text.c_str(), &stop, 10);
            if (errno == 0 && stop && *stop == '\0') {
                out = Json::make_int(value);
                return true;
            }
        }
        out = Json::make_number(std::strtod(text.c_str(), nullptr));
        return true;
    }
};

void escape_string(const std::string& text, std::string& out) {
    out.push_back('"');
    for (unsigned char c : text) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(char(c));
                }
        }
    }
    out.push_back('"');
}

}  // namespace

Json Json::parse(const std::string& text, std::string* error) {
    Parser parser{text.data(), text.data() + text.size(), {}};
    Json value;
    bool ok = parser.parse_value(value, 0);
    if (ok) {
        parser.skip_space();
        if (parser.p != parser.end) {
            ok = false;
            parser.fail("trailing characters");
        }
    }
    if (!ok && error) *error = parser.error;
    return ok ? value : Json();
}

Json Json::make_bool(bool value) {
    Json json;
    json.type_ = Type::Bool;
    json.bool_ = value;
    return json;
}

Json Json::make_number(double value) {
    Json json;
    json.type_ = Type::Number;
    json.number_ = value;
    return json;
}

Json Json::make_int(long long value) {
    Json json;
    json.type_ = Type::Number;
    json.int_form_ = true;
    json.int_ = value;
    json.number_ = double(value);
    return json;
}

Json Json::make_string(std::string value) {
    Json json;
    json.type_ = Type::String;
    json.string_ = std::move(value);
    return json;
}

Json Json::make_array() {
    Json json;
    json.type_ = Type::Array;
    return json;
}

Json Json::make_object() {
    Json json;
    json.type_ = Type::Object;
    return json;
}

bool Json::as_bool(bool fallback) const {
    if (type_ == Type::Bool) return bool_;
    if (type_ == Type::Number) return number_ != 0.0;
    return fallback;
}

double Json::as_double(double fallback) const {
    if (type_ == Type::Number) return int_form_ ? double(int_) : number_;
    return fallback;
}

long long Json::as_int(long long fallback) const {
    if (type_ == Type::Number) {
        return int_form_ ? int_ : (long long)number_;
    }
    return fallback;
}

const std::string& Json::as_string() const {
    static const std::string empty;
    return type_ == Type::String ? string_ : empty;
}

size_t Json::size() const {
    if (type_ == Type::Array) return array_.size();
    if (type_ == Type::Object) return object_.size();
    if (type_ == Type::String) return string_.size();
    return 0;
}

const Json& Json::operator[](size_t index) const {
    static const Json null;
    if (type_ == Type::Array && index < array_.size()) return array_[index];
    return null;
}

const Json* Json::find(const std::string& key) const {
    if (type_ != Type::Object) return nullptr;
    for (const auto& field : object_) {
        if (field.first == key) return &field.second;
    }
    return nullptr;
}

void Json::push(Json value) {
    if (type_ != Type::Array) {
        type_ = Type::Array;
        array_.clear();
    }
    array_.push_back(std::move(value));
}

void Json::set(std::string key, Json value) {
    if (type_ != Type::Object) {
        type_ = Type::Object;
        object_.clear();
    }
    for (auto& field : object_) {
        if (field.first == key) {
            field.second = std::move(value);
            return;
        }
    }
    object_.emplace_back(std::move(key), std::move(value));
}

std::string Json::dump() const {
    std::string out;
    dump_to(out);
    return out;
}

void Json::dump_to(std::string& out) const {
    switch (type_) {
        case Type::Null: out += "null"; break;
        case Type::Bool: out += bool_ ? "true" : "false"; break;
        case Type::Number: {
            char buf[48];
            if (int_form_) {
                std::snprintf(buf, sizeof(buf), "%lld", int_);
            } else {
                std::snprintf(buf, sizeof(buf), "%.15g", number_);
            }
            out += buf;
            break;
        }
        case Type::String: escape_string(string_, out); break;
        case Type::Array:
            out.push_back('[');
            for (size_t i = 0; i < array_.size(); ++i) {
                if (i) out.push_back(',');
                array_[i].dump_to(out);
            }
            out.push_back(']');
            break;
        case Type::Object:
            out.push_back('{');
            for (size_t i = 0; i < object_.size(); ++i) {
                if (i) out.push_back(',');
                escape_string(object_[i].first, out);
                out.push_back(':');
                object_[i].second.dump_to(out);
            }
            out.push_back('}');
            break;
    }
}
