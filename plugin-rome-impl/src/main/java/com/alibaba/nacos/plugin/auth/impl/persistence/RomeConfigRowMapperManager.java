package com.alibaba.nacos.plugin.auth.impl.persistence;

import com.alibaba.nacos.config.server.model.ConfigInfo;
import com.alibaba.nacos.config.server.service.repository.RowMapperManager;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * rome config plugin row mapper manager.
 * @author caoxingming
 * @name RomeConfigRowMapperManager
 * @date 2023-04-06-5:41 PM
 * @description: 来伊份个性化配置 row mapper manager.
 */
public class RomeConfigRowMapperManager {

    public static final RomeConfigInfoRowMapper ROME_CONFIG_INFO_ROW_MAPPER_ROW_MAPPER = new RomeConfigInfoRowMapper();

    static {
        // USER_ROW_MAPPER
        RowMapperManager.registerRowMapper(ROME_CONFIG_INFO_ROW_MAPPER_ROW_MAPPER.getClass().getCanonicalName(), ROME_CONFIG_INFO_ROW_MAPPER_ROW_MAPPER);
    }

    public static final class RomeConfigInfoRowMapper implements RowMapper<ConfigInfo> {

        @Override
        public ConfigInfo mapRow(ResultSet rs, int rowNum) throws SQLException {
            ConfigInfo info = new ConfigInfo();

            info.setDataId(rs.getString("data_id"));
            info.setGroup(rs.getString("group_id"));
            info.setTenant(rs.getString("tenant_id"));
            info.setAppName(rs.getString("app_name"));

            try {
                info.setContent(rs.getString("content"));
            } catch (SQLException ignore) {
            }
            try {
                info.setMd5(rs.getString("md5"));
            } catch (SQLException ignore) {
            }
            try {
                info.setId(rs.getLong("id"));
            } catch (SQLException ignore) {
            }
            try {
                info.setType(rs.getString("type"));
            } catch (SQLException ignore) {
            }
            try {
                info.setEncryptedDataKey(rs.getString("encrypted_data_key"));
            } catch (SQLException ignore) {
            }
            return info;
        }
    }
}
