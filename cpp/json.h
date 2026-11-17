// Minimal JSON value + parser, enough for the Stratum v1 protocol.
//
// Numbers keep their integer form when they are written without '.' or an
// exponent, so request ids and nonces round-trip unchanged.
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Json() = default;

    static Json parse(const std::string& text, std::string* error);
    static Json make_null() { return Json(); }
    static Json make_bool(bool value);
    static Json make_number(double value);
    static Json make_int(long long value);
    static Json make_string(std::string value);
    static Json make_array();
    static Json make_object();

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }
    bool is_bool() const { return type_ == Type::Bool; }
    bool is_number() const { return type_ == Type::Number; }
    bool is_string() const { return type_ == Type::String; }
    bool is_array() const { return type_ == Type::Array; }
    bool is_object() const { return type_ == Type::Object; }

    bool as_bool(bool fallback = false) const;
    double as_double(double fallback = 0.0) const;
    long long as_int(long long fallback = 0) const;
    const std::string& as_string() const;

    size_t size() const;
    const Json& operator[](size_t index) const;
    const Json* find(const std::string& key) const;
    const std::vector<Json>& items() const { return array_; }
    const std::vector<std::pair<std::string, Json>>& fields() const {
        return object_;
    }

    void push(Json value);
    void set(std::string key, Json value);

    std::string dump() const;

private:
    void dump_to(std::string& out) const;

    Type type_ = Type::Null;
    bool bool_ = false;
    bool int_form_ = false;
    long long int_ = 0;
    double number_ = 0.0;
    std::string string_;
    std::vector<Json> array_;
    std::vector<std::pair<std::string, Json>> object_;
};
