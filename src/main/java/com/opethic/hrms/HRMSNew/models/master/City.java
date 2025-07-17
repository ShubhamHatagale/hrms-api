package com.opethic.hrms.HRMSNew.models.master;

import lombok.Data;
import javax.persistence.*;

@Data
@Entity
@Table(name = "city_tbl")
public class City {

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        @Column(nullable = false, length = 50)
        private String name;

        // Removed columnDefinition and kept default mapping
        private Long stateId;

        private String stateCode;

        private Long countryId;

        // Optional: if you want this to be exactly CHAR(2), use length and let Hibernate handle it
        @Column(length = 2)
        private String countryCode;
}
