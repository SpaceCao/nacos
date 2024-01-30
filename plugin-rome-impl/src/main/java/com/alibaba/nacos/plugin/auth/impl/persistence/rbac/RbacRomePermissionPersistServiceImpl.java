package com.alibaba.nacos.plugin.auth.impl.persistence.rbac;

import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.config.server.configuration.ConditionOnExternalStorage;
import com.alibaba.nacos.config.server.model.Page;
import com.alibaba.nacos.config.server.service.repository.PaginationHelper;
import com.alibaba.nacos.config.server.service.repository.extrnal.ExternalStoragePersistServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Conditional;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * @author caoxingming
 * @name AbacRomePermissionPersistServiceImpl
 * @data 2023-04-03-6:51 PM
 * @description: 来伊份个性化权限持久层 impl.
 */
@Conditional(value = ConditionOnExternalStorage.class)
@Component
public class RbacRomePermissionPersistServiceImpl implements RbacRomePermissionPersistService {

    @Autowired
    private ExternalStoragePersistServiceImpl persistService;

    @Override
    public Page<RbacRomePermissionInfo> findRomePermissionByRoleAndDataid(String role, String dataid, int pageNo, int pageSize) {

        PaginationHelper<RbacRomePermissionInfo> helper = persistService.createPaginationHelper();

        String sqlCountRows = "SELECT count(1) FROM rome_role_server_permissions ";

        String sqlFetchRows = "SELECT role, data_id, action FROM rome_role_server_permissions ";

        StringBuilder where = new StringBuilder(" WHERE 1 = 1 ");
        List<String> params = new ArrayList<>();
        if (StringUtils.isNotBlank(role)) {
            where.append(" AND role = ? ");
            params.add(role);
        }
        if (StringUtils.isNotBlank(dataid)) {
            where.append(" AND data_id = ? ");
            params.add(dataid);
        }

        return helper.fetchPage(sqlCountRows + where, sqlFetchRows + where, params.toArray(), pageNo, pageSize,
                RbacRomeAuthRowMapperManager.ROME_PERMISSION_ROW_MAPPER);
    }
}
