package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Principles;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PrincipleRepository extends JpaRepository<Principles,Long> {



    List<Principles> findAllByStatus(boolean b);

    Principles findByPrincipleNameIgnoreCaseAndStatus(String key, boolean b);

    Principles findByIdAndStatus(Long ledgeIdpc, boolean b);

}
