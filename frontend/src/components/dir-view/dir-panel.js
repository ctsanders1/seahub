import React, { Fragment } from 'react';
import PropTypes from 'prop-types';
import cookie from 'react-cookies';
import { gettext } from '../../utils/constants';
import { seafileAPI } from '../../utils/seafile-api';
import CommonToolbar from '../toolbar/common-toolbar';
import ViewModeToolbar from '../toolbar/view-mode-toolbar';
import DirOperationToolBar from '../toolbar/dir-operation-toolbar';
import MutipleDirOperationToolbar from '../toolbar/mutilple-dir-operation-toolbar';
import CurDirPath from '../cur-dir-path';
import DirentListView from '../dirent-list-view/dirent-list-view';
import DirentDetail from '../dirent-detail/dirent-details';
import FileUploader from '../file-uploader/file-uploader';

const propTypes = {
  path: PropTypes.string.isRequired,
  repoID: PropTypes.string.isRequired,
  repoName: PropTypes.string.isRequired,
  currentRepo: PropTypes.string.isRequired,
  serviceUrl: PropTypes.string.isRequired,
  pathExist: PropTypes.bool.isRequired,
  permission: PropTypes.bool.isRequired,
  isDirentListLoading: PropTypes.bool.isRequired,
  isDirentSelected: PropTypes.bool.isRequired,
  isAllDirentSelected: PropTypes.bool.isRequired,
  direntList: PropTypes.array.isRequired,
  selectedDirentList: PropTypes.array.isRequired,
  onItemClick: PropTypes.func.isRequired,
  onAddFile: PropTypes.func.isRequired,
  onAddFolder: PropTypes.func.isRequired,
  onItemMove: PropTypes.func.isRequired,
  onItemCopy: PropTypes.func.isRequired,
  onItemRename: PropTypes.func.isRequired,
  onItemDelete: PropTypes.func.isRequired,
  onItemSelected: PropTypes.func.isRequired,
  onItemsCopy: PropTypes.func.isRequired,
  onItemsMove: PropTypes.func.isRequired,
  onItemsDelete: PropTypes.func.isRequired,
  onAllItemSelected: PropTypes.func.isRequired,
  onFileTagChanged: PropTypes.func.isRequired,
  onMenuClick: PropTypes.func.isRequired,
  onPathClick: PropTypes.func.isRequired,
  updateDirent: PropTypes.func.isRequired,
  onSearchedClick: PropTypes.func.isRequired,
  onFileSuccess: PropTypes.func.isRequired,
};

class DirPanel extends React.Component {

  constructor(props) {
    super(props);
    this.state = {
      direntPath: null,
      currentDirent: null,
      currentMode: 'list',
      isDirentDetailShow: false,
      isRepoOwner: true,
    };
  }

  componentDidMount() {
    let currentRepo = this.props.currentRepo;
    if (currentRepo) {
      seafileAPI.getAccountInfo().then(res => {
        let user_email = res.data.email;
        let isRepoOwner = currentRepo.owner_email === user_email;
        this.setState({isRepoOwner: isRepoOwner});
      });
    }
  }

  onItemDetails = (dirent, direntPath) => {
    this.setState({
      currentDirent: dirent,
      direntPath: direntPath,
      isDirentDetailShow: true,
    });
  }

  onItemDetailsClose = () => {
    this.setState({isDirentDetailShow: false});
  }

  onUploadFile = (e) => {
    e.nativeEvent.stopImmediatePropagation();
    this.uploader.onFileUpload();
  }

  onUploadFolder = (e) => {
    e.nativeEvent.stopImmediatePropagation();
    this.uploader.onFolderUpload();
  }

  switchViewMode = (mode) => {
    let { path, serviceUrl, repoID } = this.props;
    if (mode === this.state.currentMode) {
      return;
    }
    if (mode === 'wiki') {
      var url = serviceUrl + '/wiki/lib/' + repoID + path;      
      window.location = url;
    }
    cookie.save('view_mode', mode, { path: '/' });
    
    this.setState({currentMode: mode});
  }

  render() {
    const ErrMessage = (<div className="message empty-tip err-message"><h2>{gettext('Folder does not exist.')}</h2></div>);

    return (
      <div className="main-panel wiki-main-panel o-hidden">
        <div className="main-panel-north">
          <div className="cur-view-toolbar border-left-show">
            <span className="sf2-icon-menu hidden-md-up d-md-none side-nav-toggle" title={gettext('Side Nav Menu')} onClick={this.props.onMenuClick}></span>
            <div className="dir-operation">
              {this.props.isDirentSelected ?
                <MutipleDirOperationToolbar
                  path={this.props.path}
                  repoID={this.props.repoID}
                  selectedDirentList={this.props.selectedDirentList}
                  onItemsMove={this.props.onItemsMove}
                  onItemsCopy={this.props.onItemsCopy}
                  onItemsDelete={this.props.onItemsDelete}
                /> :
                <DirOperationToolBar 
                  path={this.props.path}
                  repoID={this.props.repoID}
                  serviceUrl={this.props.serviceUrl}
                  onAddFile={this.props.onAddFile}
                  onAddFolder={this.props.onAddFolder}
                  onUploadFile={this.onUploadFile}
                  onUploadFolder={this.onUploadFolder}
                />
              }
            </div>
            <ViewModeToolbar
              currentMode={this.state.currentMode} 
              switchViewMode={this.switchViewMode}
            />
          </div>
          <CommonToolbar 
            repoID={this.props.repoID} 
            onSearchedClick={this.props.onSearchedClick} 
            searchPlaceholder={'Search files in this library'}
          />
        </div>
        <div className="main-panel-center flex-direction-row">
          <div className="cur-view-container">
            <div className="cur-view-path">
              <CurDirPath 
                repoID={this.props.repoID}
                repoName={this.props.repoName}
                currentPath={this.props.path} 
                permission={this.props.permission}
                onPathClick={this.props.onPathClick}
              />
            </div>
            <div className="cur-view-content">
              {!this.props.pathExist ?
                ErrMessage :
                <Fragment>
                  <DirentListView
                    path={this.props.path}
                    repoID={this.props.repoID}
                    serviceUrl={this.props.serviceUrl}
                    direntList={this.props.direntList}
                    currentRepo={this.props.currentRepo}
                    isDirentListLoading={this.props.isDirentListLoading}
                    isAllItemSelected={this.props.isAllDirentSelected}
                    isRepoOwner={this.state.isRepoOwner}
                    onItemDetails={this.onItemDetails}
                    onItemMove={this.props.onItemMove}
                    onItemCopy={this.props.onItemCopy}
                    onItemClick={this.props.onItemClick}
                    onItemDelete={this.props.onItemDelete}
                    onItemRename={this.props.onItemRename}
                    onItemSelected={this.props.onItemSelected}
                    onAllItemSelected={this.props.onAllItemSelected}
                    updateDirent={this.props.updateDirent}
                  />
                  <FileUploader
                    dragAndDrop={true}
                    ref={uploader => this.uploader = uploader}
                    path={this.props.path}
                    repoID={this.props.repoID}
                    direntList={this.props.direntList}
                    onFileSuccess={this.props.onFileSuccess}
                  />
                </Fragment>
              }
            </div>
          </div>
          {this.state.isDirentDetailShow && (
            <div className="cur-view-detail">
              <DirentDetail
                repoID={this.props.repoID}
                serviceUrl={this.props.serviceUrl}
                dirent={this.state.currentDirent}
                direntPath={this.state.direntPath}
                onFileTagChanged={this.props.onFileTagChanged}
                onItemDetailsClose={this.onItemDetailsClose}
              />
            </div>
          )}
        </div>
      </div>
    );
  }
}

DirPanel.propTypes = propTypes;

export default DirPanel;