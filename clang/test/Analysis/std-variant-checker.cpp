// RUN: %clang %s -Xclang -verify --analyze \
// RUN:   -Xclang -analyzer-checker=core \
// RUN:   -Xclang -analyzer-checker=debug.ExprInspection \
// RUN:   -Xclang -analyzer-checker=core,core.StdVariant

#include <cstdio>
#include <type_traits>
#include <initializer_list>
#include <utility>

namespace std {
  // class template variant
  template<class... Types>
    class variant;
 
  // variant helper classes
  template<class T> struct variant_size;                        // not defined
  template<class T> struct variant_size<const T>;
  template<class T>
    inline constexpr size_t variant_size_v = variant_size<T>::value;
 
  template<class... Types>
    struct variant_size<variant<Types...>>;
 
  template<size_t I, class T> struct variant_alternative;       // not defined
  template<size_t I, class T> struct variant_alternative<I, const T>;
  template<size_t I, class T>
    using variant_alternative_t = typename variant_alternative<I, T>::type;
 
  template<size_t I, class... Types>
    struct variant_alternative<I, variant<Types...>>;
 
  inline constexpr size_t variant_npos = -1;
 
  // value access
  template<class T, class... Types>
    constexpr bool holds_alternative(const variant<Types...>&) noexcept;
 
  template<size_t I, class... Types>
    constexpr variant_alternative_t<I, variant<Types...>>& get(variant<Types...>&);
  template<size_t I, class... Types>
    constexpr variant_alternative_t<I, variant<Types...>>&& get(variant<Types...>&&);
  template<size_t I, class... Types>
    constexpr const variant_alternative_t<I, variant<Types...>>&
      get(const variant<Types...>&);
  template<size_t I, class... Types>
    constexpr const variant_alternative_t<I, variant<Types...>>&&
      get(const variant<Types...>&&);
 
  template<class T, class... Types>
    constexpr T& get(variant<Types...>&);
  template<class T, class... Types>
    constexpr T&& get(variant<Types...>&&);
  template<class T, class... Types>
    constexpr const T& get(const variant<Types...>&);
  template<class T, class... Types>
    constexpr const T&& get(const variant<Types...>&&);
 
  template<size_t I, class... Types>
    constexpr add_pointer_t<variant_alternative_t<I, variant<Types...>>>
      get_if(variant<Types...>*) noexcept;
  template<size_t I, class... Types>
    constexpr add_pointer_t<const variant_alternative_t<I, variant<Types...>>>
      get_if(const variant<Types...>*) noexcept;
 
  template<class T, class... Types>
    constexpr add_pointer_t<T>
      get_if(variant<Types...>*) noexcept;
  template<class T, class... Types>
    constexpr add_pointer_t<const T>
      get_if(const variant<Types...>*) noexcept;
 
  // relational operators
  template<class... Types>
    constexpr bool operator==(const variant<Types...>&, const variant<Types...>&);
  template<class... Types>
    constexpr bool operator!=(const variant<Types...>&, const variant<Types...>&);
  template<class... Types>
    constexpr bool operator<(const variant<Types...>&, const variant<Types...>&);
  template<class... Types>
    constexpr bool operator>(const variant<Types...>&, const variant<Types...>&);
  template<class... Types>
    constexpr bool operator<=(const variant<Types...>&, const variant<Types...>&);
  template<class... Types>
    constexpr bool operator>=(const variant<Types...>&, const variant<Types...>&);
 
  // visitation
  template<class R, class Visitor, class... Variants>
    constexpr R visit(Visitor&&, Variants&&...);
 
  // class monostate
  struct monostate;
 
  // monostate relational operators
  constexpr bool operator==(monostate, monostate) noexcept;
 
  // specialized algorithms
  template<class... Types>
    constexpr void swap(variant<Types...>&,
                        variant<Types...>&);
 
  // class bad_variant_access
  class bad_variant_access;
 
  // hash support
  template<class T> struct hash;
  template<class... Types> struct hash<variant<Types...>>;
  template<> struct hash<monostate>;
}
 
// deprecated
namespace std {
  template<class T> struct variant_size<volatile T>;
  template<class T> struct variant_size<const volatile T>;
 
  template<size_t I, class T> struct variant_alternative<I, volatile T>;
  template<size_t I, class T> struct variant_alternative<I, const volatile T>;
}

namespace std {
  template<class... Types>
  class variant {
  public:
    // constructors
    constexpr variant();
    constexpr variant(const variant&);
    constexpr variant(variant&&);
 
    template<class T>
      constexpr variant(T&&);
 
    template<class T, class... Args>
      variant(in_place_type_t<T>, Args&&...);
    template<class T, class U, class... Args>
      variant(in_place_type_t<T>, initializer_list<U>, Args&&...);
 
    template<size_t I, class... Args>
      variant(in_place_index_t<I>, Args&&...);
    template<size_t I, class U, class... Args>
      variant(in_place_index_t<I>, initializer_list<U>, Args&&...);
 
    // destructor
    ~variant();
 
    // assignment
    constexpr variant& operator=(const variant&);
    constexpr variant& operator=(variant&&);
 
    template<class T> constexpr variant& operator=(T&&) ;
 
    // modifiers
    template<class T, class... Args>
      constexpr T& emplace(Args&&...);
    template<class T, class U, class... Args>
      constexpr T& emplace(initializer_list<U>, Args&&...);
    template<size_t I, class... Args>
      constexpr variant_alternative_t<I, variant<Types...>>& emplace(Args&&...);
    template<size_t I, class U, class... Args>
      constexpr variant_alternative_t<I, variant<Types...>>&
        emplace(initializer_list<U>, Args&&...);
 
    // value status
    constexpr bool valueless_by_exception() const noexcept;
    constexpr size_t index() const noexcept;
 
    // swap
    constexpr void swap(variant&) ;
  };
}

class Foo{};

void clang_analyzer_warnIfReached();
void clang_analyzer_eval(int);

//helper functions
void changeVariantType(std::variant<int, char> &v) {
  v = 25;
}

void changesToInt(std::variant<int, char> &v);
void changesToInt(std::variant<int, char> *v);

void cannotChangePtr(const std::variant<int, char> &v);
void cannotChangePtr(const std::variant<int, char> *v);

char getUnknownChar();

void swap(std::variant<int, char> &v1, std::variant<int, char> &v2) {
  std::variant<int, char> tmp = v1;
  v1 = v2;
  v2 = tmp;
}

void cantDo(const std::variant<int, char>& v) {
  std::variant<int, char> vtmp = v;
  vtmp = 5;
  int a = std::get<int> (vtmp);
  (void*) a;
}

void changeVariantPtr(std::variant<int, char> *v) {
  *v = 'c';
}

using var_t = std::variant<int, char>;
using var_tt = var_t;
using int_t = int;
using char_t = char;


//----------------------------------------------------------------------------//
// std::get
//----------------------------------------------------------------------------//
// Verify that we warn when we try to get the wrong type out of variant by
// passing the index of the type and we do not warn when we try to get
// the stored type


void stdGetType() {
  std::variant<int, char> v = 25;
  int a = std::get<int>(v);
  char c = std::get<char>(v); // expected-warning {{std::variant 'v' held a(n) int not a(n) char}}
  (void*)a;
  (void*)c;
}

void stdGetPointer() {
  std::variant<int*, char> v = new int;
  int *a = std::get<int*>(v);
  char c = std::get<char>(v); // expected-warning {{std::variant 'v' held a(n) int * not a(n) char}}
  (void**)a;
  (void*)c;
}

void stdGetObject() {
  std::variant<int, char, Foo> v = Foo{};
  Foo f = std::get<Foo>(v);
  int i = std::get<int>(v); // expected-warning {{std::variant 'v' held a(n) Foo not a(n) int}}
  (void*)i;
}

void stdGetPointerAndPointee() {
  int a = 5;
  std::variant<int, int*> v = &a;
  int *b = std::get<int*>(v);
  int c = std::get<int>(v); // expected-warning {{std::variant 'v' held a(n) int * not a(n) int}}
  (void*)c;
  (void**)b;
}

//----------------------------------------------------------------------------//
// Constructors and assignments
//----------------------------------------------------------------------------//
void copyConstructor() {
  std::variant<int, char> v = 25;
  std::variant<int, char> t(v);
  int a = std::get<int> (t);
  char c = std::get<char> (t); // expected-warning {{std::variant 't' held a(n) int not a(n) char}}
  (void*)a;
  (void*)c;
}

void copyAssignemntOperator() {
  std::variant<int, char> v = 25;
  std::variant<int, char> t = 'c';
  t = v;
  int a = std::get<int> (t);
  char c = std::get<char> (t); // expected-warning {{std::variant 't' held a(n) int not a(n) char}}
  (void*)a;
  (void*)c;
}

void assignemntOperator() {
  std::variant<int, char> v = 25;
  int a = std::get<int> (v);
  (void*)a;
  v = 'c';
  char c = std::get<char>(v);
  a = std::get<int>(v); // expected-warning {{std::variant 'v' held a(n) char not a(n) int}}
  (void*)a;
  (void*)c;
}

void defaultConstructor() {
  std::variant<int, char> v;
  int i = std::get<int>(v);
  char c = std::get<char>(v); // expected-warning {{std::variant 'v' held a(n) int not a(n) char}}
  (void*)i;
  (void*)c;
}

// Verify that we handle temporary objects correctly
void temporaryObjectsConstructor() {
  std::variant<int, char> v(std::variant<int, char>('c'));
  char c = std::get<char>(v);
  int a = std::get<int>(v); // expected-warning {{std::variant 'v' held a(n) char not a(n) int}}
  (void*)a;
  (void*)c;
}

void temporaryObjectsAssignment() {
  std::variant<int, char> v = std::variant<int, char>('c');
  char c = std::get<char>(v);
  int a = std::get<int>(v); // expected-warning {{std::variant 'v' held a(n) char not a(n) int}}
  (void*)a;
  (void*)c;
}

// Verify that we handle pointer types correctly
void pointerTypeHeld() {
  std::variant<int*, char> v = new int;
  int *a = std::get<int*>(v);
  char c = std::get<char>(v); // expected-warning {{std::variant 'v' held a(n) int * not a(n) char}}
  (void**)a;
  (void*)c;
}

std::variant<int, char> get_unknown_variant();
// Verify that the copy constructor is handles properly when the std::variant
// has no previously activated type and we copy an object of unknown value in it.
void copyFromUnknownVariant() {
  std::variant<int, char> u = get_unknown_variant();
  std::variant<int, char> v(u);
  int a = std::get<int>(v); // no-waring
  char c = std::get<char>(v); // no-warning
  (void*)a;
  (void*)c;
}

// Verify that the copy constructor is handles properly when the std::variant
// has previously activated type and we copy an object of unknown value in it.
void copyFromUnknownVariantBef() {
  std::variant<int, char> v = 25;
  std::variant<int, char> u = get_unknown_variant();
  v = u;
  int a = std::get<int>(v); // no-waring
  char c = std::get<char>(v); // no-warning
  (void*)a;
  (void*)c;
}

//----------------------------------------------------------------------------//
// typedef
//----------------------------------------------------------------------------//

void typefdefedVariant() {
  var_t v = 25;
  int a = std::get<int>(v);
  char c = std::get<char>(v); // expected-warning {{std::variant 'v' held a(n) int not a(n) char}}
  (void*)a;
  (void*)c;
}

void typedefedTypedfefedVariant() {
  var_tt v = 25;
  int a = std::get<int>(v);
  char c = std::get<char>(v); // expected-warning {{std::variant 'v' held a(n) int not a(n) char}}
  (void*)a;
  (void*)c;
}

void typdefedGet() {
  std::variant<char, int> v = 25;
  int a = std::get<int_t>(v);
  char c = std::get<char_t>(v); // expected-warning {{std::variant 'v' held a(n) int not a(n) char}}
  (void*)a;
  (void*)c;
}

void typedefedPack() {
  std::variant<int_t, char_t> v = 25;
  int a = std::get<int>(v);
  char c = std::get<char>(v); // expected-warning {{std::variant 'v' held a(n) int not a(n) char}}
  (void*)a;
  (void*)c;
}

void fromVariable() {
  char o = 'c';
  std::variant<int, char> v(o);
  char c = std::get<char>(v);
  int a = std::get<int>(v); // expected-warning {{std::variant 'v' held a(n) char not a(n) int}}
  (void*)a;
  (void*)c;
}

void unknowValueButKnownType() {
  char o = getUnknownChar();
  std::variant<int, char> v(o);
  char c = std::get<char>(v);
  int a = std::get<int>(v); // expected-warning {{std::variant 'v' held a(n) char not a(n) int}}
  (void*)a;
  (void*)c;
}

void createPointer() {
  std::variant<int, char> *v = new std::variant<int, char>(15);
  int a = std::get<int>(*v);
  char c = std::get<char>(*v); // expected-warning {{std::variant  held a(n) int not a(n) char}}
  (void*)a;
  (void*)c;
}

//----------------------------------------------------------------------------//
// Passing std::variants to functions
//----------------------------------------------------------------------------//

// Verifying that we are not invalidating the memory region of a variant if
// a non inlined or inlined funtion takes it as a constant reference or pointer
void constNonInlineRef() {
  std::variant<int, char> v = 'c';
  cannotChangePtr(v);
  char c = std::get<char>(v);
  int a = std::get<int>(v); // expected-warning {{std::variant 'v' held a(n) char not a(n) int}}
  (void*)a;
  (void*)c;
}

void contNonInlinePtr() {
  std::variant<int, char> v = 'c';
  cannotChangePtr(&v);
  char c = std::get<char>(v);
  int a = std::get<int>(v); // expected-warning {{std::variant 'v' held a(n) char not a(n) int}}
  (void*)a;
  (void*)c;
}

void copyInAFunction() {
  std::variant<int, char> v = 'c';
  cantDo(v);
  char c = std::get<char>(v);
  int a = std::get<int>(v); // expected-warning {{std::variant 'v' held a(n) char not a(n) int}}
  (void*)a;
  (void*)c;

}

// Verifying that we can keep track of the type stored in std::variant when
// it is passed to an inlined funtion as a reference or pointer
void changeThruPointers() {
  std::variant<int, char> v = 15;
  changeVariantPtr(&v);
  char c = std::get<char> (v);
  int a = std::get<int> (v); // expected-warning {{std::variant 'v' held a(n) char not a(n) int}}
  (void*)a;
  (void*)c;
}

void functionCallWithCopyAssignment() {
  var_t v1 = 15;
  var_t v2 = 'c';
  swap(v1, v2);
  int a = std::get<int> (v2);
  (void*)a;
  char c = std::get<char> (v1);
  a = std::get<int> (v1); // expected-warning {{std::variant 'v1' held a(n) char not a(n) int}}
  (void*)a;
  (void*)c;
}

void inlineFunctionCall() {
  std::variant<int, char> v = 'c';
  changeVariantType(v);
  int a = std::get<int> (v);
  char c = std::get<char> (v); // expected-warning {{std::variant 'v' held a(n) int not a(n) char}}
  (void*)a;
  (void*)c;
}

// Verifying that we invalidate the mem region of std::variant when it is
// passed as a referenece or a pointer to a non inlined function
void nonInleneFunctionCall() {
  std::variant<int, char> v = 'c';
  changesToInt(v);
  int a = std::get<int> (v); // no-waring
  char c = std::get<char> (v); // no-warning
  (void*)a;
  (void*)c;
}

void nonInleneFunctionCallPtr() {
  std::variant<int, char> v = 'c';
  changesToInt(&v);
  int a = std::get<int> (v); // no-warning
  char c = std::get<char> (v); // no-warning
  (void*)a;
  (void*)c;
}


//What we do not report on, but we should
void valueHeld() {
  std::variant<int, char> v = 0;
  int a = std::get<int>(v);
  clang_analyzer_eval(0 == a); // expected-warning{{TRUE}}
  int div = 10/a; // we should report a divison by 0 here
  clang_analyzer_warnIfReached(); // no-warning
  (void*)div;
  (void*)a;
}

void stdGetIf() {
  std::variant<int, char> v = 'c';
  int* i = std::get_if<int>(&v);
  clang_analyzer_eval(nullptr == i); // expected-warning{{TRUE}}
  (*i)++; //we should report a dereference of a null pointer here
  clang_analyzer_warnIfReached(); // no-warning
  (void**)i;
}
