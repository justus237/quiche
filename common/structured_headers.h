// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_COMMON_STRUCTURED_HEADERS_H_
#define QUICHE_COMMON_STRUCTURED_HEADERS_H_

#include <algorithm>
#include <map>
#include <string>
#include <tuple>
#include <vector>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "common/platform/api/quiche_export.h"
#include "common/platform/api/quiche_logging.h"

namespace quiche {
namespace structured_headers {

// This file implements parsing of HTTP structured headers, as defined in
// RFC8941 (https://www.rfc-editor.org/rfc/rfc8941.html). For compatibility with
// the shipped implementation of Web Packaging, this file also supports a
// previous revision of the standard, referred to here as "Draft 9".
// (https://datatracker.ietf.org/doc/draft-ietf-httpbis-header-structure/09/)
//
// The major difference between the two revisions is in the various list
// formats: Draft 9 describes "parameterised lists" and "lists-of-lists", while
// the final RFC uses a single "list" syntax, whose members may be inner lists.
// There should be no ambiguity, however, as the code which calls this parser
// should be expecting only a single type for a given header.
//
// References within the code are tagged with either [SH09] or [RFC8941],
// depending on which revision they refer to.
//
// Currently supported data types are:
//  Item:
//   integer: 123
//   string: "abc"
//   token: abc
//   byte sequence: *YWJj*
//  Parameterised list: abc_123;a=1;b=2; cdef_456, ghi;q="9";r="w"
//  List-of-lists: "foo";"bar", "baz", "bat"; "one"
//  List: "foo", "bar", "It was the best of times."
//        ("foo" "bar"), ("baz"), ("bat" "one"), ()
//        abc;a=1;b=2; cde_456, (ghi jkl);q="9";r=w
//  Dictionary: a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid=?0
//
// Functions are provided to parse each of these, which are intended to be
// called with the complete value of an HTTP header (that is, any
// sub-structure will be handled internally by the parser; the exported
// functions are not intended to be called on partial header strings.) Input
// values should be ASCII byte strings (non-ASCII characters should not be
// present in Structured Header values, and will cause the entire header to fail
// to parse.)

class QUICHE_EXPORT_PRIVATE Item {
 public:
  enum ItemType {
    kNullType,
    kIntegerType,
    kDecimalType,
    kStringType,
    kTokenType,
    kByteSequenceType,
    kBooleanType
  };
  Item();
  explicit Item(int64_t value);
  explicit Item(double value);
  explicit Item(bool value);

  // Constructors for string-like items: Strings, Tokens and Byte Sequences.
  Item(const char* value, Item::ItemType type = kStringType);
  Item(const std::string& value, Item::ItemType type = kStringType);
  Item(std::string&& value, Item::ItemType type = kStringType);

  QUICHE_EXPORT_PRIVATE friend bool operator==(const Item& lhs,
                                               const Item& rhs);
  inline friend bool operator!=(const Item& lhs, const Item& rhs) {
    return !(lhs == rhs);
  }

  bool is_null() const { return type_ == kNullType; }
  bool is_integer() const { return type_ == kIntegerType; }
  bool is_decimal() const { return type_ == kDecimalType; }
  bool is_string() const { return type_ == kStringType; }
  bool is_token() const { return type_ == kTokenType; }
  bool is_byte_sequence() const { return type_ == kByteSequenceType; }
  bool is_boolean() const { return type_ == kBooleanType; }

  int64_t GetInteger() const {
    QUICHE_CHECK_EQ(type_, kIntegerType);
    return integer_value_;
  }
  double GetDecimal() const {
    QUICHE_CHECK_EQ(type_, kDecimalType);
    return decimal_value_;
  }
  bool GetBoolean() const {
    QUICHE_CHECK_EQ(type_, kBooleanType);
    return boolean_value_;
  }
  // TODO(iclelland): Split up accessors for String, Token and Byte Sequence.
  const std::string& GetString() const {
    QUICHE_CHECK(type_ == kStringType || type_ == kTokenType ||
                 type_ == kByteSequenceType);
    return string_value_;
  }

  ItemType Type() const { return type_; }

 private:
  ItemType type_ = kNullType;
  // TODO(iclelland): Make this class more memory-efficient, replacing the
  // values here with a union or std::variant (when available).
  int64_t integer_value_ = 0;
  std::string string_value_;
  double decimal_value_;
  bool boolean_value_;
};

// Holds a ParameterizedIdentifier (draft 9 only). The contained Item must be a
// Token, and there may be any number of parameters. Parameter ordering is not
// significant.
struct QUICHE_EXPORT_PRIVATE ParameterisedIdentifier {
  using Parameters = std::map<std::string, Item>;

  Item identifier;
  Parameters params;

  ParameterisedIdentifier(const ParameterisedIdentifier&);
  ParameterisedIdentifier& operator=(const ParameterisedIdentifier&);
  ParameterisedIdentifier(Item, const Parameters&);
  ~ParameterisedIdentifier();
};

inline bool operator==(const ParameterisedIdentifier& lhs,
                       const ParameterisedIdentifier& rhs) {
  return std::tie(lhs.identifier, lhs.params) ==
         std::tie(rhs.identifier, rhs.params);
}

using Parameters = std::vector<std::pair<std::string, Item>>;

struct QUICHE_EXPORT_PRIVATE ParameterizedItem {
  Item item;
  Parameters params;

  ParameterizedItem(const ParameterizedItem&);
  ParameterizedItem& operator=(const ParameterizedItem&);
  ParameterizedItem(Item, const Parameters&);
  ~ParameterizedItem();
};

inline bool operator==(const ParameterizedItem& lhs,
                       const ParameterizedItem& rhs) {
  return std::tie(lhs.item, lhs.params) == std::tie(rhs.item, rhs.params);
}

inline bool operator!=(const ParameterizedItem& lhs,
                       const ParameterizedItem& rhs) {
  return !(lhs == rhs);
}

// Holds a ParameterizedMember, which may be either an single Item, or an Inner
// List of ParameterizedItems, along with any number of parameters. Parameter
// ordering is significant.
struct QUICHE_EXPORT_PRIVATE ParameterizedMember {
  std::vector<ParameterizedItem> member;
  // If false, then |member| should only hold one Item.
  bool member_is_inner_list = false;

  Parameters params;

  ParameterizedMember();
  ParameterizedMember(const ParameterizedMember&);
  ParameterizedMember& operator=(const ParameterizedMember&);
  ParameterizedMember(std::vector<ParameterizedItem>, bool member_is_inner_list,
                      const Parameters&);
  // Shorthand constructor for a member which is an inner list.
  ParameterizedMember(std::vector<ParameterizedItem>, const Parameters&);
  // Shorthand constructor for a member which is a single Item.
  ParameterizedMember(Item, const Parameters&);
  ~ParameterizedMember();
};

inline bool operator==(const ParameterizedMember& lhs,
                       const ParameterizedMember& rhs) {
  return std::tie(lhs.member, lhs.member_is_inner_list, lhs.params) ==
         std::tie(rhs.member, rhs.member_is_inner_list, rhs.params);
}

using DictionaryMember = std::pair<std::string, ParameterizedMember>;

// Structured Headers RFC8941 Dictionary.
class QUICHE_EXPORT_PRIVATE Dictionary {
 public:
  using iterator = std::vector<DictionaryMember>::iterator;
  using const_iterator = std::vector<DictionaryMember>::const_iterator;

  Dictionary();
  Dictionary(const Dictionary&);
  explicit Dictionary(std::vector<DictionaryMember> members);
  ~Dictionary();
  Dictionary& operator=(const Dictionary&) = default;
  iterator begin();
  const_iterator begin() const;
  iterator end();
  const_iterator end() const;

  // operator[](size_t) and at(size_t) will both abort the program in case of
  // out of bounds access.
  ParameterizedMember& operator[](std::size_t idx);
  const ParameterizedMember& operator[](std::size_t idx) const;
  ParameterizedMember& at(std::size_t idx);
  const ParameterizedMember& at(std::size_t idx) const;

  // Consistent with std::map, if |key| does not exist in the Dictionary, then
  // operator[](absl::string_view) will create an entry for it, but at() will
  // abort the entire program.
  ParameterizedMember& operator[](absl::string_view key);
  ParameterizedMember& at(absl::string_view key);
  const ParameterizedMember& at(absl::string_view key) const;

  bool empty() const;
  std::size_t size() const;
  bool contains(absl::string_view key) const;
  friend bool operator==(const Dictionary& lhs, const Dictionary& rhs);
  friend bool operator!=(const Dictionary& lhs, const Dictionary& rhs);

 private:
  // Uses a vector to hold pairs of key and dictionary member. This makes
  // look up by index and serialization much easier.
  std::vector<DictionaryMember> members_;
};

inline bool operator==(const Dictionary& lhs, const Dictionary& rhs) {
  return lhs.members_ == rhs.members_;
}

inline bool operator!=(const Dictionary& lhs, const Dictionary& rhs) {
  return !(lhs == rhs);
}

// Structured Headers Draft 09 Parameterised List.
using ParameterisedList = std::vector<ParameterisedIdentifier>;
// Structured Headers Draft 09 List of Lists.
using ListOfLists = std::vector<std::vector<Item>>;
// Structured Headers RFC8941 List.
using List = std::vector<ParameterizedMember>;

// Returns the result of parsing the header value as an Item, if it can be
// parsed as one, or nullopt if it cannot. Note that this uses the Draft 15
// parsing rules, and so applies tighter range limits to integers.
QUICHE_EXPORT_PRIVATE absl::optional<ParameterizedItem> ParseItem(
    absl::string_view str);

// Returns the result of parsing the header value as an Item with no parameters,
// or nullopt if it cannot. Note that this uses the Draft 15 parsing rules, and
// so applies tighter range limits to integers.
QUICHE_EXPORT_PRIVATE absl::optional<Item> ParseBareItem(absl::string_view str);

// Returns the result of parsing the header value as a Parameterised List, if it
// can be parsed as one, or nullopt if it cannot. Note that parameter keys will
// be returned as strings, which are guaranteed to be ASCII-encoded. List items,
// as well as parameter values, will be returned as Items. This method uses the
// Draft 09 parsing rules for Items, so integers have the 64-bit int range.
// Structured-Headers Draft 09 only.
QUICHE_EXPORT_PRIVATE absl::optional<ParameterisedList> ParseParameterisedList(
    absl::string_view str);

// Returns the result of parsing the header value as a List of Lists, if it can
// be parsed as one, or nullopt if it cannot. Inner list items will be returned
// as Items. This method uses the Draft 09 parsing rules for Items, so integers
// have the 64-bit int range.
// Structured-Headers Draft 09 only.
QUICHE_EXPORT_PRIVATE absl::optional<ListOfLists> ParseListOfLists(
    absl::string_view str);

// Returns the result of parsing the header value as a general List, if it can
// be parsed as one, or nullopt if it cannot.
// Structured-Headers Draft 15 only.
QUICHE_EXPORT_PRIVATE absl::optional<List> ParseList(absl::string_view str);

// Returns the result of parsing the header value as a general Dictionary, if it
// can be parsed as one, or nullopt if it cannot. Structured-Headers Draft 15
// only.
QUICHE_EXPORT_PRIVATE absl::optional<Dictionary> ParseDictionary(
    const absl::string_view& str);

// Serialization is implemented for Structured-Headers Draft 15 only.
QUICHE_EXPORT_PRIVATE absl::optional<std::string> SerializeItem(
    const Item& value);
QUICHE_EXPORT_PRIVATE absl::optional<std::string> SerializeItem(
    const ParameterizedItem& value);
QUICHE_EXPORT_PRIVATE absl::optional<std::string> SerializeList(
    const List& value);
QUICHE_EXPORT_PRIVATE absl::optional<std::string> SerializeDictionary(
    const Dictionary& value);

}  // namespace structured_headers
}  // namespace quiche

#endif  // QUICHE_COMMON_STRUCTURED_HEADERS_H_
