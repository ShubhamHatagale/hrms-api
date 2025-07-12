package com.opethic.hrms.HRMSNew.repositories.master;


import com.opethic.hrms.HRMSNew.models.master.PrincipleGroups;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PrincipleGroupsRepository extends JpaRepository<PrincipleGroups, Long> {
    PrincipleGroups findByIdAndStatus(long principle_group_id, boolean b);

    PrincipleGroups findByGroupNameIgnoreCase(String s);

    List<PrincipleGroups> findAllByStatus(boolean b);
    

}
