// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Current manual credential state only (Constitution III; data-model §1.9). */
@Entity
@Table(name = "configured_tokens")
@SuppressWarnings("NullAway.Init") // Hibernate initializes the mapped fields.
public class ConfiguredToken {
    @Id
    public String label;
    @Column(name = "verifier", nullable = false)
    public byte[] verifier;
}
