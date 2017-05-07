#include "vigenerecipher.h"

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <numeric>
#include <vector>

#include "loopreader.h"

ribi::VigenereCipher::VigenereCipher(const std::string& s)
  : m_key(StrToKey(s))
{
  #ifndef NDEBUG
  TestVigenereCipher();
  #endif
  if (!IsClean(s))
  {
    throw std::logic_error("Vigenere cipher key may have uppercase characters only");
  }
}

std::string ribi::Clean(const std::string& s) noexcept
{
  std::string t;
  std::copy_if(s.begin(),s.end(),std::back_inserter(t),
    [](const char c)
    {
      const char d = std::tolower(c);
      return d >= 'a' && d <= 'z';
    }
  );
  std::for_each(t.begin(),t.end(),
    [](char& c) { c = std::tolower(c); }
  );
  assert(IsClean(t));
  return t;
}

std::string ribi::VigenereCipher::Deencrypt(std::string s) const
{
  if (!IsClean(s))
  {
    throw std::logic_error("Vigenere cipher text may have uppercase characters only");
  }

  const int sz = static_cast<int>(s.size());
  for (int i=0; i!=sz; ++i)
  {
    const char c = s[i];
    assert(c >= 'a');
    assert(c <= 'z');
    const int key = m_key[ i % m_key.size() ];
    assert(key >= 0);
    assert(key  < 26);
    s[i] = Deencrypt(c,key);
    assert(c >= 'a');
    assert(c <= 'z');
  }
  return s;
}

char ribi::VigenereCipher::Deencrypt(const char c, const int d) const noexcept
{
  assert(c >= 'a');
  assert(c <= 'z');
  const int i = static_cast<int>(c - 'a');
  const int i_new = (((i - d) % 26) + 26) % 26;
  assert(i_new >= 0);
  assert(i_new < 26);
  const char r = static_cast<char>('a' + i_new);
  assert(d != 0 || c == r);
  assert(r >= 'a');
  assert(r <= 'z');
  return r;
}


std::string ribi::VigenereCipher::Encrypt(std::string s) const
{
  if (!IsClean(s))
  {
    throw std::logic_error("Vigenere plain text may have uppercase characters only");
  }

  const int sz = static_cast<int>(s.size());
  for (int i=0; i!=sz; ++i)
  {
    const char c = s[i];
    assert(c >= 'a');
    assert(c <= 'z');
    assert(m_key.size() > 0);
    const int key = m_key[ i % m_key.size() ];
    assert(key >= 0);
    assert(key  < 26);
    s[i] = Encrypt(c,key);
    assert(c >= 'a');
    assert(c <= 'z');
  }
  return s;
}


char ribi::VigenereCipher::Encrypt(const char c, const int d) const noexcept
{
  assert(c >= 'a');
  assert(c <= 'z');
  const int i = static_cast<int>(c - 'a');
  const int i_new = (((i + d) % 26) + 26) % 26;
  assert(i_new >= 0);
  assert(i_new < 26);
  const char r = static_cast<char>('a' + i_new);
  assert(d != 0 || c == r);
  assert(r >= 'a');
  assert(r <= 'z');
  return r;
}


std::string ribi::GetVigenereCipherVersion() noexcept
{
  return "1.1";
}

std::vector<std::string> ribi::GetVigenereCipherVersionHistory() noexcept
{
  return {
    "2014-04-01: version 1.0: initial version",
    "2014-04-07: version 1.1: use lowercase characters, added Clean and IsClean member functions"
  };
}

bool ribi::IsClean(const std::string& s) noexcept
{
  for (const auto& c:s) { if (c < 'a' || c > 'z') return false; }
  return true;
}

std::vector<int> ribi::StrToKey(const std::string& s) noexcept
{
  std::vector<int> v;
  for (const auto& c: s)
  {
    //Uppercase only
    assert(c >= 'a');
    assert(c <= 'z');
    const int i = static_cast<int>(c - 'a');
    v.push_back(i);
  }
  return v;
}

void ribi::TestVigenereCipher() noexcept
{
  {
    static bool is_tested{false};
    if (is_tested) return;
    is_tested = true;
  }
  {
    const VigenereCipher e("a");
    const std::string s = "abcdefghijk";
    assert(s == e.Encrypt(s));
    assert(s == e.Deencrypt(s));
  }
  {
    const std::vector<std::string> v {
      "abcdefghijklmnopqrstuvwxyz",
      "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
      "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
    };
    for (const std::string& s: v)
    {

      for (const std::string& key: { "ab", "abc", "abcde"} )
      {

        const VigenereCipher e(key);
        const std::string clean_text = Clean(s);
        assert(e.Deencrypt(e.Encrypt(clean_text)) == clean_text);
        //Test encryption with real, decryption with faker
        const VigenereCipher faker(key + "x");
        assert(faker.Deencrypt(e.Encrypt(clean_text)) != clean_text);
      }
    }
  }
  {
    const std::string key = "key";
    const std::string secret = "oweifjowergsergrthtrhtrhrhergergef";
    const VigenereCipher e(key);
    const std::string clean_text = Clean(secret);
  }
}
