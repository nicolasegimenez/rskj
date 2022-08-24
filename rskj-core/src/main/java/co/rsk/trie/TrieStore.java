/*
 * This file is part of RskJ
 * Copyright (C) 2017 RSK Labs Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package co.rsk.trie;

import java.util.List;
import java.util.Optional;

public interface TrieStore {
    // This method assures consistency: if a top node is really saved, then all child nodes must
    // also be saved. In case of failure, some subtrees may be saved, but never the top node.
    void save(Trie trie);

    void flush();

    /**
     * @param hash the root of the {@link Trie} to retrieve
     * @return an optional containing the {@link Trie} with <code>rootHash</code> if found
     */
    Optional<Trie> retrieve(byte[] hash);

    byte[] retrieveValue(byte[] hash);

    void dispose();


    /*
     * This method is used for logging, debugging and monitoring.
     * Implementor can retrieve any relevant information regarding the state
     * of the data source, such as number of gets, puts, etc.
     * If no imformation is available, it can return simply null.
     */
    List<String> getStats();

    /*
    * This method returns a name given to this trie store. It is used for easy debugging and
    * logging.
    */
    String getName();

    /* This is a forced save of the cache to disk
     * Only used in testing performance to create a cache file for a certain height.
     */
    default void saveCache() {}
}
