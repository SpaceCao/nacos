package com.alibaba.nacos.plugin.auth.impl.persistence.abac;

import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.config.server.configuration.ConditionOnExternalStorage;
import com.alibaba.nacos.config.server.model.Page;
import com.alibaba.nacos.config.server.service.datasource.DataSourceService;
import com.alibaba.nacos.config.server.service.datasource.DynamicDataSource;
import com.alibaba.nacos.config.server.service.repository.PaginationHelper;
import com.alibaba.nacos.config.server.service.repository.extrnal.ExternalStoragePersistServiceImpl;
import com.alibaba.nacos.config.server.utils.LogUtil;
import com.alibaba.nacos.plugin.auth.impl.persistence.AuthRowMapperManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Conditional;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.jdbc.core.JdbcTemplate;
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
public class AbacRomePermissionPersistServiceImpl implements AbacRomePermissionPersistService {

    private DataSourceService dataSourceService;

    protected JdbcTemplate jt;

    @Autowired
    private ExternalStoragePersistServiceImpl persistService;

    public static final AuthRowMapperManager.AbacRomePermissionRowMapper ROME_PERMISSION_ROW_MAPPER = new AuthRowMapperManager.AbacRomePermissionRowMapper();

    public AbacRomePermissionPersistServiceImpl() {
        this.dataSourceService = DynamicDataSource.getInstance().getDataSource();
        this.jt = dataSourceService.getJdbcTemplate();
    }

    @Override
    public List<AbacRomePermissionInfo> findRomePermissionByDataidAndUsername(String dataid, String username) {

        String sqlFetchRows = "SELECT role, data_id, action FROM rome_server_permissions ";

        StringBuilder where = new StringBuilder(" WHERE 1 = 1 ");
        List<String> params = new ArrayList<>();
        if (StringUtils.isNotBlank(username)) {
            where.append(" AND username = ? ");
            params.add(username);
        }
        if (StringUtils.isNotBlank(dataid)) {
            where.append(" AND data_id = ? ");
            params.add(dataid);
        }

        try {
            return this.jt.query(sqlFetchRows + where.toString(), params.toArray(), ROME_PERMISSION_ROW_MAPPER);
        } catch (CannotGetJdbcConnectionException e) {
            LogUtil.FATAL_LOG.error("[db-error] ", e);
            throw e;
        } catch (Exception e) {
            throw e;
        }
    }

    @Override
    public Page<AbacRomePermissionInfo> findRomePermissionByUsernameAndDataid(String username, String dataid, int pageNo, int pageSize) {

        PaginationHelper<AbacRomePermissionInfo> helper = persistService.createPaginationHelper();

        String sqlCountRows = "SELECT count(1) FROM rome_server_permissions ";

        String sqlFetchRows = "SELECT role, data_id, action FROM rome_server_permissions ";

        StringBuilder where = new StringBuilder(" WHERE 1 = 1 ");
        List<String> params = new ArrayList<>();
        if (StringUtils.isNotBlank(username)) {
            where.append(" AND username = ? ");
            params.add(username);
        }
        if (StringUtils.isNotBlank(dataid)) {
            where.append(" AND data_id = ? ");
            params.add(dataid);
        }

        return helper.fetchPage(sqlCountRows + where, sqlFetchRows + where, params.toArray(), pageNo, pageSize,
                AbacRomeAuthRowMapperManager.ROME_PERMISSION_ROW_MAPPER);
    }
}
