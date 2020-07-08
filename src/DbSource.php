<?php

/*
 * Copyright (c) 2019-2020 François Kooman <fkooman@tuxed.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace fkooman\SAML\SP;

use PDO;

class DbSource implements SourceInterface
{
    /** @var \PDO */
    private $db;

    public function __construct(PDO $db)
    {
        $this->db = $db;
    }

    /**
     * Get SAML metadata.
     *
     * @param string $entityId
     *
     * @return string|null
     */
    public function get($entityId)
    {
        $stmt = $this->db->prepare(
<<< 'SQL'
    SELECT
        entity_metadata
    FROM saml_entities
    WHERE
        entity_id = :entity_id
SQL
        );

        $stmt->bindValue(':entity_id', $entityId, PDO::PARAM_STR);
        $stmt->execute();

        if (null === $idpMetadata = $stmt->fetchColumn(0)) {
            return null;
        }

        return (string) $idpMetadata;
    }

    /**
     * @param string $entityId
     * @param string $entityMetadata
     *
     * @return void
     */
    public function add($entityId, $entityMetadata)
    {
        $stmt = $this->db->prepare(
<<< 'SQL'
    INSERT INTO
        saml_entities (entity_id, entity_metadata)
    VALUES
        (:entity_id, :entity_metadata)
SQL
        );
        $stmt->bindValue(':entity_id', $entityId, PDO::PARAM_STR);
        $stmt->bindValue(':entity_metadata', $entityMetadata, PDO::PARAM_STR);
        $stmt->execute();
    }

    /**
     * @return void
     */
    public function init()
    {
        $this->db->exec(
<<< 'SQL'
    CREATE TABLE IF NOT EXISTS saml_entities (
        entity_id VARCHAR(255) NOT NULL,
        entity_metadata TEXT NOT NULL,
        UNIQUE(entity_id)
    )
SQL
        );
    }
}
