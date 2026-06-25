#pragma once
#include <unordered_map>

template<typename Key, typename Meta>
class VaultIndex
{
    std::unordered_map<Key, Meta> paths;

public:
    std::unordered_map<Key, Meta> &getPaths(){ return paths; }
    const std::unordered_map<Key, Meta> &getPaths() const{ return paths; }
    bool contains(const Key &k) const{ return paths.find(k) != paths.end(); }
};