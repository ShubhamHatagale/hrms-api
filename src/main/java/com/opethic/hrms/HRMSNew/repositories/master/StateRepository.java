package com.opethic.hrms.HRMSNew.repositories.master;


import com.opethic.hrms.HRMSNew.models.master.State;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface StateRepository extends JpaRepository<State, Long> {
    List<State> findByCountryCode(String in);

    State findByStateCode(String stateCode);
}
