/*
 * Copyright 1999-2021 Alibaba Group Holding Ltd.
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

package com.alibaba.nacos.plugin.auth.impl.persistence.abac;

import com.alibaba.nacos.config.server.service.repository.RowMapperManager;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;


/**
  * Auth plugin row mapper manager.
  * @author: caoxingming
  * @date: 2023/4/11 11:20 AM
  * @description: Auth plugin row mapper manager.
  **/
public class AbacRomeAuthRowMapperManager {

    public static final RomePermissionRowMapper ROME_PERMISSION_ROW_MAPPER = new RomePermissionRowMapper();

    static {

        //ROME_PERMISSION_ROW_MAPPER
        RowMapperManager.registerRowMapper(ROME_PERMISSION_ROW_MAPPER.getClass().getCanonicalName(), ROME_PERMISSION_ROW_MAPPER);
    }



    public static final class RomePermissionRowMapper implements RowMapper<AbacRomePermissionInfo> {

        @Override
        public AbacRomePermissionInfo mapRow(ResultSet rs, int rowNum) throws SQLException {
            AbacRomePermissionInfo info = new AbacRomePermissionInfo();
            info.setUsername(rs.getString("username"));
            info.setDataId(rs.getString("data_id"));
            info.setAction(rs.getString("action"));
            return info;
        }
    }
}
