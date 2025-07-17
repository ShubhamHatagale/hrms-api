package com.opethic.hrms.HRMSNew.models.master;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "state_tbl")
public class State {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private Long countryId;

    // Removed columnDefinition to let Hibernate handle it correctly
    @Column(length = 2)
    private String countryCode;

    private String stateCode;
}
