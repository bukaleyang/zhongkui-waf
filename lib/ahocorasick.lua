--[[
    A Lua implementation of the Aho-Corasick string matching algorithm.

    Copyright 2023 bukale bukale2022@163.com

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
]]

local stringutf8 = require "stringutf8"
local arrays = require "arrays"
local nkeys = require "table.nkeys"
local isempty = require "table.isempty"

local newtab = table.new
local sort = table.sort
local insert = table.insert
local remove = table.remove
local setmetatable = setmetatable
local pairs = pairs
local ipairs = ipairs

local to_char_array = stringutf8.to_char_array
local trim = stringutf8.trim
local lower = string.lower

local _AhoCorasick = {}
_AhoCorasick.VERSION = "v0.1"

local CHILDREN_ARRAY_LIMIT = 6

local _TrieNode = {}

local mt_trienode = {__index = _TrieNode,
                    __eq = function(a, b)
                        return a.word == b.word
                    end,
                    __lt = function(a, b)
                        return a.word < b.word
                    end,
                    __tostring = function (t)
                        return t.word
                    end}

function _TrieNode:new(word, depth)
    local t = {
            word = word,
            children = nil,
            isChildrenArray = false,
            isEnd = false,
            count = 1,
            fail = nil,
            depth = depth and depth or 1}

    setmetatable(t, mt_trienode)
    return t
end

local _Trie = {}
local mt_trie = {__index = _Trie}

function _Trie:new(arrayLimit)
    local t = {
            rootNode = _TrieNode:new("/"),
            childrenArrayLimit = arrayLimit and arrayLimit or CHILDREN_ARRAY_LIMIT
        }

    setmetatable(t, mt_trie)
    return t
end

function _Trie:addNodes(str)
    if not str or str == '' or type(str) ~= "string" then
        return
    end
    str = trim(str)
    str = lower(str)

    local current = self.rootNode
    local array = to_char_array(str)
    for i, word in ipairs(array) do
        local children = current.children
        if not children then
            if self.childrenArrayLimit > 0 then
                children = newtab(self.childrenArrayLimit, 0)
            else
                children = newtab(0, self.childrenArrayLimit)
            end
        end

        local node
		local storedSize = nkeys(children)
        if self.childrenArrayLimit > 0 and storedSize < self.childrenArrayLimit then
            node = _TrieNode:new(word, i)
            local pos = arrays.binary_search(children, 1, storedSize, node)
            if pos > 0 then
                node = children[pos]
                node.count = node.count + 1
            else
                children[storedSize + 1] = node
                sort(children, function(a, b)
                    return a.word < b.word
                end)
            end

            current.children = children
            current.isChildrenArray = true
        else
            local isArray = current.isChildrenArray
            if storedSize > 0 and isArray then
                local newChildren = newtab(0, self.childrenArrayLimit + 1)
                for _, v in ipairs(children) do
                    newChildren[v.word] = v
                end
                --current.children = newChildren
                children = newChildren
                current.isChildrenArray = false
            end

            node = children[word]
            if node then
                node.count = node.count + 1
            else
                node = _TrieNode:new(word, i)
                children[word] = node
            end

            current.children = children
        end
        current = node
    end
    current.isEnd = true

    return self.rootNode
end

function _Trie:contains(str)
    if not str or str == "" or type(str) ~= "string" then
        return false
    end
    local current = self.rootNode
    local children
    local array = to_char_array(str)
    for _, word in ipairs(array) do
        children = current.children
        if children then
            local isArray = current.isChildrenArray
            if isArray then
                local storedSize = nkeys(children)
                local pos = arrays.binary_search(children, 1, storedSize, _TrieNode:new(word))

                if pos > 0 then
                    current = children[pos]
                else
                    return false
                end
            else
                current = children[word]
            end
        else
            return false
        end
    end

    if current.isEnd then
        return true
    end

    return false
end

local mt_ac = {__index = _AhoCorasick}

function _AhoCorasick:new(arrayLimit)
    local t = {
            trie = _Trie:new(arrayLimit),
            builded = false
        }

    setmetatable(t, mt_ac)
    return t
end

local function pop(t)
    if t then
        local element = t[1]
        remove(t, 1)
        return element
    end
end

local function push(t, e)
    if t then
        insert(t, e)
    end
end

local function getFail(self, childNode, fatherFail)
    local fail
    local children = fatherFail.children
    if children then
        local isArray = fatherFail.isChildrenArray
        if isArray then
            local storedSize = nkeys(children)
            local pos = arrays.binary_search(children, 1, storedSize, childNode)
            if pos > 0 then
                fail = children[pos]
            end
        else
            local word = childNode.word
            local temp = children[word]
            if temp then
                fail = temp
            end
        end
    end


    if fail then
        return fail
    end

    if fatherFail == self.trie.rootNode then
        return fatherFail
    end

    return getFail(self, childNode, fatherFail.fail)
end

function _AhoCorasick:buildFail()
    local trie = self.trie
    local rootNode = trie.rootNode

    rootNode.fail = rootNode
    local queue = {}
    push(queue, rootNode)

    while nkeys(queue) > 0 do
        local parrent = pop(queue)
        if not parrent then
            break
        end

        local fatherFail = parrent.fail
        local children = parrent.children
        if children then
            for _, child in pairs(children) do

                if parrent == rootNode and child ~= rootNode then
                    child.fail = rootNode
                else
                    local failNode = getFail(self, child, fatherFail)
                    child.fail = failNode
                end

                push(queue, child)
            end
        end
    end

    self.builded = true
end

function _AhoCorasick:add(words)
    if not words then
        return
    end

    local trie = self.trie
    local paramType = type(words)
    if paramType == 'table' then
        if not isempty(words) then
            for _, w in ipairs(words) do
                trie:addNodes(w)
            end
        end
    elseif paramType == 'string' then
        trie:addNodes(words)
    else
        error('table or string expected, got ' .. paramType)
    end

    self.builded = false
end

function _AhoCorasick:match(str, simpleMode)
    if not str or str == '' then
        return
    end

    local array = to_char_array(str)
    if isempty(array) then
        return
    end

    if not self.builded then
        self:buildFail()
    end

    local result = {}
    local rootNode = self.trie.rootNode
    local current = rootNode

    for i, word in ipairs(array) do
        while true do
            local children = current.children
            if children then
                local isArray = current.isChildrenArray
                if isArray then
                    local pos = arrays.binary_search(children, 1, nkeys(children), _TrieNode:new(word))
                    if pos > 0 then
                        current = children[pos]
                        break
                    end
                else
                    local temp = children[word]
                    if temp then
                        current = temp
                        break
                    end
                end
            end

            if current ~= rootNode then
                current = current.fail
            else
                break
            end
        end

        if not current then
            current = rootNode
        end

        local temp = current
        while temp ~= rootNode do
            if temp.isEnd then
                if simpleMode == true then
                    insert(result, stringutf8.sub(str, i - temp.depth + 1, i))
                else
                    local from, to = i - temp.depth + 1, i
                    local words = stringutf8.sub(str, from, to)
                    insert(result, {words = words, from = from, to = to})
                end
            end
            temp = temp.fail
        end
    end

    return result
end

return _AhoCorasick