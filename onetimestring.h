#ifndef ONETIMESTRING_H
#define ONETIMESTRING_H

#include <iostream>
#include <string>
#include <type_traits>

#include <QString>


char const * const __DEL_STR__ = "DEL_STR";


template <typename T, typename = typename
std::enable_if<
    std::is_same<std::string, T>::value ||
    std::is_same<char const *, T>::value ||
    std::is_same<QString, T>::value
>::type>
struct OneTimeString{

    explicit OneTimeString(T const& initStr__)    :
        Str_{new T{initStr__}}
    {}

~OneTimeString(){ delete Str_; }

    T const getStr()
    {
        if(Str_){

            T const __tempS = *Str_;
            delete Str_;
            Str_=nullptr;
            return __tempS;
        }

        return __DEL_STR__/*<std::string>*/;
    }

private:
    T* Str_=nullptr;

    OneTimeString() = delete;

    OneTimeString(OneTimeString const&) = delete;
    OneTimeString& operator=(OneTimeString const&) = delete;
};

#endif // ONETIMESTRING_H
