/*
 * Copyright 1999-2018 Alibaba Group Holding Ltd.
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

import React from 'react';
import PropTypes from 'prop-types';
import {
  Button,
  Dialog,
  Pagination,
  Table,
  ConfigProvider,
  Form,
  Input,
  Switch,
} from '@alifd/next';
import { connect } from 'react-redux';
import { getPermissions, createPermission, deletePermission } from '../../../reducers/authority';
import { getNamespaces } from '../../../reducers/namespace';
import RegionGroup from '../../../components/RegionGroup';
import NewPermissions from './NewPermissions';

import './PermissionsManagement.scss';

@connect(
  state => ({
    permissions: state.authority.permissions,
    namespaces: state.namespace.namespaces,
  }),
  { getPermissions, getNamespaces }
)
@ConfigProvider.config
class PermissionsManagement extends React.Component {
  static displayName = 'PermissionsManagement';

  static propTypes = {
    locale: PropTypes.object,
    permissions: PropTypes.object,
    namespaces: PropTypes.array,
    getPermissions: PropTypes.func,
    getNamespaces: PropTypes.func,
  };

  constructor(props) {
    super(props);
    this.state = {
      loading: true,
      pageNo: 1,
      pageSize: 9,
      createPermission: false,
      defaultFuzzySearch: true,
      role: '',
    };
    this.handleDefaultFuzzySwitchChange = this.handleDefaultFuzzySwitchChange.bind(this);
  }

  componentDidMount() {
    this.getPermissions();
    this.props.getNamespaces();
  }

  getPermissions() {
    this.setState({ loading: true });
    const { pageNo, pageSize } = this.state;
    let { role } = this.state;
    let search = 'accurate';
    if (this.state.defaultFuzzySearch) {
      if (role && role !== '') {
        role = `*${role}*`;
      }
    }
    if (role && role.indexOf('*') !== -1) {
      search = 'blur';
    }
    this.props
      .getPermissions({ pageNo, pageSize, role, search })
      .then(() => {
        if (this.state.loading) {
          this.setState({ loading: false });
        }
      })
      .catch(() => this.setState({ loading: false }));
  }

  colseCreatePermission() {
    this.setState({ createPermissionVisible: false });
  }

  getActionText(action) {
    const { locale } = this.props;
    return {
      r: `${locale.readOnly} (r)`,
      w: `${locale.writeOnly} (w)`,
      rw: `${locale.readWrite} (rw)`,
    }[action];
  }

  handleDefaultFuzzySwitchChange() {
    this.setState({ defaultFuzzySearch: !this.state.defaultFuzzySearch });
  }

  render() {
    const { permissions, namespaces = [], locale } = this.props;
    const { loading, pageSize, pageNo, createPermissionVisible } = this.state;
    return (
      <>
        <RegionGroup left={locale.privilegeManagement} />
        <Form inline>
          <Form.Item label={locale.role}>
            <Input
              value={this.state.role}
              htmlType="text"
              placeholder={this.state.defaultFuzzySearch ? locale.defaultFuzzyd : locale.fuzzyd}
              style={{ width: 200 }}
              onChange={role => {
                this.setState({ role });
              }}
            />
          </Form.Item>
          <Form.Item label={locale.fuzzydMode}>
            <Switch
              checkedChildren=""
              unCheckedChildren=""
              defaultChecked={this.state.defaultFuzzySearch}
              onChange={this.handleDefaultFuzzySwitchChange}
              title={locale.fuzzyd}
            />
          </Form.Item>
          <Form.Item label={''}>
            <Button
              type={'primary'}
              style={{ marginRight: 10 }}
              onClick={() => this.getPermissions()}
              data-spm-click={'gostr=/aliyun;locaid=dashsearch'}
            >
              {locale.query}
            </Button>
          </Form.Item>
          <Form.Item style={{ float: 'right' }}>
            <Button
              type="primary"
              onClick={() => this.setState({ createPermissionVisible: true })}
              style={{ marginRight: 20 }}
            >
              {locale.addPermission}
            </Button>
          </Form.Item>
        </Form>
        <Table dataSource={permissions.pageItems} loading={loading} maxBodyHeight={476} fixedHeader>
          <Table.Column title={locale.role} dataIndex="role" />
          <Table.Column
            title={locale.resource}
            dataIndex="resource"
            cell={value => {
              const [item = {}] = namespaces.filter(({ namespace }) => {
                const [itemNamespace] = value.split(':');
                return itemNamespace === namespace;
              });
              const { namespaceShowName = '', namespace = '' } = item;
              return namespaceShowName + (namespace ? ` (${namespace})` : '');
            }}
          />
          <Table.Column
            title={locale.action}
            dataIndex="action"
            cell={action => this.getActionText(action)}
          />
          <Table.Column
            title={locale.operation}
            cell={(value, index, record) => (
              <>
                <Button
                  type="primary"
                  warning
                  onClick={() =>
                    Dialog.confirm({
                      title: locale.deletePermission,
                      content: locale.deletePermissionTip,
                      onOk: () =>
                        deletePermission(record).then(() => {
                          this.setState({ pageNo: 1 }, () => this.getPermissions());
                        }),
                    })
                  }
                >
                  {locale.deletePermission}
                </Button>
              </>
            )}
          />
        </Table>
        {permissions.totalCount > pageSize && (
          <Pagination
            className="users-pagination"
            current={pageNo}
            total={permissions.totalCount}
            pageSize={pageSize}
            onChange={pageNo => this.setState({ pageNo }, () => this.getPermissions())}
          />
        )}
        <NewPermissions
          visible={createPermissionVisible}
          onOk={permission =>
            createPermission(permission).then(res => {
              this.setState({ pageNo: 1 }, () => this.getPermissions());
              return res;
            })
          }
          onCancel={() => this.colseCreatePermission()}
        />
      </>
    );
  }
}

export default PermissionsManagement;
