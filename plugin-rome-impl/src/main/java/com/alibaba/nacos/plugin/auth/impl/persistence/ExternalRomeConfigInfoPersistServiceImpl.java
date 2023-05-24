/*
 * Copyright 1999-2022 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.plugin.auth.impl.persistence;

import com.alibaba.nacos.common.utils.CollectionUtils;
import com.alibaba.nacos.common.utils.Pair;
import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.config.server.configuration.ConditionOnExternalStorage;
import com.alibaba.nacos.config.server.model.ConfigAllInfo;
import com.alibaba.nacos.config.server.model.ConfigInfo;
import com.alibaba.nacos.config.server.model.Page;
import com.alibaba.nacos.config.server.service.datasource.DataSourceService;
import com.alibaba.nacos.config.server.service.datasource.DynamicDataSource;
import com.alibaba.nacos.config.server.service.repository.PaginationHelper;
import com.alibaba.nacos.config.server.service.repository.RowMapperManager;
import com.alibaba.nacos.config.server.service.repository.extrnal.ExternalStoragePersistServiceImpl;
import com.alibaba.nacos.config.server.utils.LogUtil;
import com.alibaba.nacos.plugin.auth.impl.constant.AuthConstants;
import com.alibaba.nacos.plugin.encryption.handler.EncryptionHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Conditional;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.*;


/**
  *
  * @author: caoxingming
  * @date: 2023/4/6 4:37 PM
  * @description: ExternalConfigInfoPersistServiceImpl
  **/
@SuppressWarnings(value = {"PMD.MethodReturnWrapperTypeRule", "checkstyle:linelength"})
@Conditional(value = ConditionOnExternalStorage.class)
@Service("externalRomeConfigInfoPersistServiceImpl")
public class ExternalRomeConfigInfoPersistServiceImpl implements RomeConfigInfoPersistService {

    String PATTERN_STR = "*";

    private static final String DATA_ID = "dataId";

    private static final String GROUP = "group";

    private static final String APP_NAME = "appName";


    private static final String TENANT = "tenant_id";

    private DataSourceService dataSourceService;

    @Autowired
    private ExternalStoragePersistServiceImpl persistService;

    protected JdbcTemplate jt;

    public static final RowMapperManager.ConfigAllInfoRowMapper CONFIG_ALL_INFO_ROW_MAPPER = new RowMapperManager.ConfigAllInfoRowMapper();


    public ExternalRomeConfigInfoPersistServiceImpl() {
        this.dataSourceService = DynamicDataSource.getInstance().getDataSource();
        this.jt = dataSourceService.getJdbcTemplate();
    }


    @Override
    public Page<ConfigInfo> findConfigInfo4Page(int pageNo, int pageSize, String dataId, String group, String tenant, Map<String, Object> configAdvanceInfo, List<String> roles) {
        String tenantTmp = StringUtils.isBlank(tenant) ? StringUtils.EMPTY : tenant;
        PaginationHelper<ConfigInfo> helper = persistService.createPaginationHelper();

        final String appName = configAdvanceInfo == null ? null : (String) configAdvanceInfo.get("appName");
        final String configTags = configAdvanceInfo == null ? null : (String) configAdvanceInfo.get("config_tags");
        Map<String, String> sqlMap = new HashMap<>(16);

        List<String> paramList = new ArrayList<>();
        Map<String, String> paramsMap = new HashMap<>(16);
        if(CollectionUtils.isEmpty(roles))
            return null;
        paramsMap.put(TENANT, tenantTmp);
        if (StringUtils.isNotBlank(dataId)) {
            paramsMap.put(DATA_ID, dataId);
        }
        if (StringUtils.isNotBlank(group)) {
            paramsMap.put(GROUP, group);
        }
        if (StringUtils.isNotBlank(appName)) {
            paramsMap.put(APP_NAME, appName);
        }
        final int startRow = (pageNo - 1) * pageSize;
        this.findConfigInfo(sqlMap, paramsMap, paramList, roles, configTags, startRow, pageSize);

        String sql = sqlMap.get(PageSqlType.QUERY_COUNT.toString());
        String sqlCount = sqlMap.get(PageSqlType.QUERY_FETCH.toString());

        try {
            Page<ConfigInfo> page = helper.fetchPage(sql, sqlCount, paramList.toArray(), pageNo, pageSize,
                    RomeConfigRowMapperManager.ROME_CONFIG_INFO_ROW_MAPPER_ROW_MAPPER);
            for (ConfigInfo configInfo : page.getPageItems()) {
                Pair<String, String> pair = EncryptionHandler.decryptHandler(configInfo.getDataId(),
                        configInfo.getEncryptedDataKey(), configInfo.getContent());
                configInfo.setContent(pair.getSecond());
            }
            return page;
        } catch (CannotGetJdbcConnectionException e) {
            LogUtil.FATAL_LOG.error("[db-error] ", e);
            throw e;
        }
    }

    @Override
    public List<ConfigAllInfo> findAllConfigInfo4Export(String dataId, String group, String tenant, String appName, List<Long> ids, List<String> roles) {
        boolean globalAdminRole = false;
        String tenantTmp = StringUtils.isBlank(tenant) ? StringUtils.EMPTY : tenant;
        Map<String, String> params = new HashMap<>(16);
        List<Object> paramList = new ArrayList<>();
        if(roles.contains(AuthConstants.GLOBAL_ADMIN_ROLE)) {
            globalAdminRole = true;
        }

        String sql = "SELECT a.id,a.data_id,a.group_id,a.tenant_id,a.app_name,a.content,a.type,a.md5,a.gmt_create,a.gmt_modified,a.src_user,a.src_ip,"
                + "a.c_desc,a.c_use,a.effect,a.c_schema,a.encrypted_data_key FROM config_info a ";
        if(!globalAdminRole) {
            sql += " LEFT JOIN rome_role_server_permissions c on c.data_id = a.data_id ";
        }
        StringBuilder where = new StringBuilder(" WHERE 1= 1 ");
        if(!globalAdminRole) {
            where.append(" AND c.role IN (");
            for (int i = 0; i < roles.size(); i++) {
                if (i != 0) {
                    where.append(", ");
                }
                where.append('?');
            }
            where.append(") ");
            paramList.addAll(roles);
        }
        if (!CollectionUtils.isEmpty(ids)) {
            paramList.addAll(ids);
            where.append(" AND a.id IN (");
            for (int i = 0; i < ids.size(); i++) {
                if (i != 0) {
                    where.append(", ");
                }
                where.append('?');
                paramList.add(ids.get(i));
            }
            where.append(") ");
        } else {
            where.append(" AND a.tenant_id= ? ");
            paramList.add(tenantTmp);
            if (!StringUtils.isBlank(params.get(DATA_ID))) {
                paramList.add(generateLikeArgument(dataId));
                where.append(" AND a.data_id LIKE ? ");
            }
            if (StringUtils.isNotBlank(params.get(GROUP))) {
                paramList.add(group);
                where.append(" AND a.group_id= ? ");
            }
            if (StringUtils.isNotBlank(params.get(APP_NAME))) {
                paramList.add(appName);
                where.append(" AND a.app_name= ? ");
            }
        }

        try {
            return this.jt.query(sql + where.toString(), paramList.toArray(), CONFIG_ALL_INFO_ROW_MAPPER);
        } catch (CannotGetJdbcConnectionException e) {
            LogUtil.FATAL_LOG.error("[db-error] ", e);
            throw e;
        } catch (Exception e) {
            throw e;
        }

    }

    private void findConfigInfo(Map<String, String> sqlMap, Map<String, String> paramsMap, List<String> paramList, List<String> roles, String configTags, int startRow, int pageSize) {
        boolean configTagsSwitch = false;
        boolean globalAdminRole = false;
        List<String> tags = new ArrayList<>(16);
        if(!StringUtils.isEmpty(configTags)) {
            configTagsSwitch = true;
            String[] tagArr = configTags.split(",");
            tags.addAll(Arrays.asList(tagArr));
        }

        if(roles.contains(AuthConstants.GLOBAL_ADMIN_ROLE)) {
            globalAdminRole = true;
        }

        final String appName = paramsMap.get(APP_NAME);
        final String dataId = paramsMap.get(DATA_ID);
        final String group = paramsMap.get(GROUP);
        final String tenant = paramsMap.get(TENANT);
        String sqlCount = "SELECT count(1) FROM config_info  a";
        String sql = "SELECT a.id,a.data_id,a.group_id,a.tenant_id,a.app_name,a.content,type,a.encrypted_data_key FROM config_info a";
        if(configTagsSwitch) {
            sqlCount += " LEFT JOIN config_tags_relation b ON a.id=b.id ";
            sql += " LEFT JOIN config_tags_relation b ON a.id=b.id ";
        }
        if(!globalAdminRole) {
            sqlCount += " LEFT JOIN rome_role_server_permissions c on c.data_id = a.data_id ";
            sql += " LEFT JOIN rome_role_server_permissions c on c.data_id = a.data_id ";
        }
        StringBuilder where = new StringBuilder(" WHERE ");
        where.append(" a.tenant_id=? ");
        paramList.add(tenant);
        if(!globalAdminRole) {
            where.append(" AND c.role IN (");
            for (int i = 0; i < roles.size(); i++) {
                if (i != 0) {
                    where.append(", ");
                }
                where.append('?');
            }
            where.append(") ");
            paramList.addAll(roles);
        }
        if (StringUtils.isNotBlank(dataId)) {
            where.append(" AND a.data_id=? ");
            paramList.add(dataId);
        }
        if (StringUtils.isNotBlank(group)) {
            where.append(" AND a.group_id=? ");
            paramList.add(group);
        }
        if (StringUtils.isNotBlank(appName)) {
            where.append(" AND a.app_name=? ");
            paramList.add(appName);
        }
        if(configTagsSwitch) {
            where.append(" AND b.tag_name IN (");
            for (int i = 0; i < tags.size(); i++) {
                if (i != 0) {
                    where.append(", ");
                }
                where.append('?');
            }
            where.append(") ");
            paramList.addAll(tags);
        }

        sql += where + " LIMIT " + startRow + "," + pageSize;
        sqlCount += where;
        sqlMap.put(PageSqlType.QUERY_FETCH.toString(),sql);
        sqlMap.put(PageSqlType.QUERY_COUNT.toString(),sqlCount);
    }


    public String generateLikeArgument(String s) {
        String fuzzySearchSign = "\\*";
        String sqlLikePercentSign = "%";
        if (s.contains(PATTERN_STR)) {
            return s.replaceAll(fuzzySearchSign, sqlLikePercentSign);
        } else {
            return s;
        }
    }


    public enum PageSqlType {
        QUERY_COUNT,QUERY_FETCH;
    }
}
