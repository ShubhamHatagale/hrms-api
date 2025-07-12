package com.opethic.hrms.HRMSNew.repositories.access_permissions_repositories;

import com.opethic.hrms.HRMSNew.models.access_permissions.SystemAccessPermissions;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SystemAccessPermissionsRepository extends JpaRepository<SystemAccessPermissions,Long> {

    List<SystemAccessPermissions> findByUsersIdAndStatus(Long id, boolean b);
    SystemAccessPermissions findByUsersIdAndStatusAndSystemActionMappingId(Long id, boolean b, Long id1);
    List<SystemAccessPermissions> findByUserRoleIdAndStatus(long roleId, boolean b);
}
