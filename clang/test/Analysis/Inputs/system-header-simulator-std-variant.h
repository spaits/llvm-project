// Like the compiler, the static analyzer treats some functions differently if
// they come from a system header

#pragma clang system_header

#include <cstdio>
#include <memory>
#include <type_traits>
#include <initializer_list>
#include <utility>
#include <assert.h>

namespace std {
  // variant
  template <class... Types> class variant;
  // variant helper classes
  template <class T> struct variant_size; // not defined
  template <class T> struct variant_size<const T>;
  template <class T> struct variant_size<volatile T>;
  template <class T> struct variant_size<const volatile T>;
  template <class T> inline constexpr size_t variant_size_v = variant_size<T>::value;
  template <class... Types>
  struct variant_size<variant<Types...>>;
  template <size_t I, class T> struct variant_alternative; // not defined
  template <size_t I, class T> struct variant_alternative<I, const T>;
  template <size_t I, class T> struct variant_alternative<I, volatile T>;
  template <size_t I, class T> struct variant_alternative<I, const volatile T>;
  template <size_t I, class T>
  using variant_alternative_t = typename variant_alternative<I, T>::type;
  template <size_t I, class... Types>
  struct variant_alternative<I, variant<Types...>>;
  inline constexpr size_t variant_npos = -1;
  // value access
  template <class T, class... Types>
  constexpr bool holds_alternative(const variant<Types...>&) noexcept;
  template <size_t I, class... Types>
  constexpr variant_alternative_t<I, variant<Types...>>&
    get(variant<Types...>&);
  template <size_t I, class... Types>
  constexpr variant_alternative_t<I, variant<Types...>>&&
    get(variant<Types...>&&);
  template <size_t I, class... Types>
  constexpr const variant_alternative_t<I, variant<Types...>>&
    get(const variant<Types...>&);
  template <size_t I, class... Types>
  constexpr const variant_alternative_t<I, variant<Types...>>&&
    get(const variant<Types...>&&);
  template <class T, class... Types>
  constexpr T& get(variant<Types...>&);
  template <class T, class... Types>
  constexpr T&& get(variant<Types...>&&);
  template <class T, class... Types>
  constexpr const T& get(const variant<Types...>&);
  template <class T, class... Types>
  constexpr const T&& get(const variant<Types...>&&);
  template <size_t I, class... Types>
  constexpr add_pointer_t<variant_alternative_t<I, variant<Types...>>>
    get_if(variant<Types...>*) noexcept;
  template <size_t I, class... Types>
  constexpr add_pointer_t<const variant_alternative_t<I, variant<Types...>>>
    get_if(const variant<Types...>*) noexcept;
  template <class T, class... Types>
  constexpr add_pointer_t<T> get_if(variant<Types...>*) noexcept;
  template <class T, class... Types>
  constexpr add_pointer_t<const T> get_if(const variant<Types...>*) noexcept;
  // relational operators
  template <class... Types>
  constexpr bool operator==(const variant<Types...>&,
  const variant<Types...>&);
  template <class... Types>
  constexpr bool operator!=(const variant<Types...>&,
  const variant<Types...>&);
  template <class... Types>
  constexpr bool operator<(const variant<Types...>&,
  const variant<Types...>&);
  template <class... Types>
  constexpr bool operator>(const variant<Types...>&,
  const variant<Types...>&);
  template <class... Types>
  constexpr bool operator<=(const variant<Types...>&,
  const variant<Types...>&);
  template <class... Types>
  constexpr bool operator>=(const variant<Types...>&,
  const variant<Types...>&);
  // visitation
  template <class Visitor, class... Variants>
  //constexpr /*see definition*/ visit(Visitor&&, Variants&&...);
  // class monostate
  struct monostate;
  // monostate relational operators
  // constexpr bool operator<(monostate, monostate) noexcept;
  // constexpr bool operator>(monostate, monostate) noexcept;
  // constexpr bool operator<=(monostate, monostate) noexcept;
  // constexpr bool operator>=(monostate, monostate) noexcept;
  // constexpr bool operator==(monostate, monostate) noexcept;
  // constexpr bool operator!=(monostate, monostate) noexcept;
  // specialized algorithms
  template <class... Types>
  void swap(variant<Types...>&, variant<Types...>&);
  // class bad_variant_access
  class bad_variant_access;
  // hash support
  // template <class T> struct hash;
  // template <class... Types> struct hash<variant<Types...>>;
  // template <> struct hash<monostate>;
  // allocator-related traits
  template <class T, class Alloc> struct uses_allocator;
  template <class... Types, class Alloc>
  struct uses_allocator<variant<Types...>, Alloc>;

  template <class... Types>
class variant {
public:
  
  
  
  // constructors
  constexpr variant()= default ;
  constexpr variant(const variant&);

  constexpr variant(variant&&);
  

  template<typename T,
            typename = std::enable_if_t<!is_same_v<decay_t<std::variant<Types...>>, remove_reference_t<decay_t<T>>>>>
	constexpr
	variant(T&&);
  
  template <class T, class... Args>
  constexpr explicit variant(in_place_type_t<T>, Args&&...);
  template <class T, class U, class... Args>
  constexpr explicit variant(in_place_type_t<T>, initializer_list<U>, Args&&...);
  template <size_t I, class... Args>
  constexpr explicit variant(in_place_index_t<I>, Args&&...);
  template <size_t I, class U, class... Args>
  constexpr explicit variant(in_place_index_t<I>, initializer_list<U>, Args&&...);
  // allocator-extended constructors
  template <class Alloc>
  variant(allocator_arg_t, const Alloc&);
  template <class Alloc>
  variant(allocator_arg_t, const Alloc&, const variant&);
  template <class Alloc>
  variant(allocator_arg_t, const Alloc&, variant&&);
  template <class Alloc, class T>
  variant(allocator_arg_t, const Alloc&, T&&);
  template <class Alloc, class T, class... Args>
  variant(allocator_arg_t, const Alloc&, in_place_type_t<T>, Args&&...);
  template <class Alloc, class T, class U, class... Args>
  variant(allocator_arg_t, const Alloc&, in_place_type_t<T>,
          initializer_list<U>, Args&&...);
  template <class Alloc, size_t I, class... Args>
  variant(allocator_arg_t, const Alloc&, in_place_index_t<I>, Args&&...);
  template <class Alloc, size_t I, class U, class... Args>
  variant(allocator_arg_t, const Alloc&, in_place_index_t<I>,
          initializer_list<U>, Args&&...);
  // destructor
  ~variant();
  // assignment
  variant& operator=(const variant&);
  variant& operator=(variant&&) ;
  template<typename T,
            typename = std::enable_if_t<!is_same_v<decay_t<std::variant<Types...>>, remove_reference_t<decay_t<T>>>>>
  variant& operator=(T&&) ;
  // modifiers
  template <class T, class... Args> void emplace(Args&&...);
  template <class T, class U, class... Args>
  void emplace(initializer_list<U>, Args&&...);
  template <size_t I, class... Args> void emplace(Args&&...);
  template <size_t I, class U, class... Args>
  void emplace(initializer_list<U>, Args&&...);
  // value status
  constexpr bool valueless_by_exception() const noexcept;
  constexpr size_t index() const noexcept;
  // swap
  void swap(variant&) ;
};
} // namespace std