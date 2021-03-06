import React from 'react';
import PropTypes from 'prop-types';
import { siteRoot } from '../../utils/constants';
import { seafileAPI } from '../../utils/seafile-api';
import { Utils } from '../../utils/utils';
import { gettext } from '../../utils/constants';
import Toast from '../toast';
import DirPanel from './dir-panel';
import Dirent from '../../models/dirent';
import FileTag from '../../models/file-tag';
import Repo from '../../models/repo';

const propTypes = {
  onMenuClick: PropTypes.func.isRequired,
  updateCurrentTab: PropTypes.func.isRequired,
};

class DirView extends React.Component {

  constructor(props) {
    super(props);

    this.state = {
      path: '/',
      pathExit: true,
      repoName: '',
      repoID: '',
      permission: true,
      isDirentSelected: false,
      isAllDirentSelected: false,
      isDirentListLoading: true,
      currentRepo: null,
      direntList: [],
      selectedDirentList: [],
    };
    window.onpopstate = this.onpopstate;
  }

  onpopstate = (event) => {
    if (event.state && event.state.path) {
      this.updateDirentList(event.state.path);
      this.setState({path: event.state.path});
    }
  }

  componentDidMount() {
    let repoID = this.props.repoID;
    seafileAPI.getRepoInfo(repoID).then(res => {
      let repo = new Repo(res.data);
      this.setState({
        repoID: repo.repo_id,
        repoName: repo.repo_name,
        permission: repo.permission === 'rw',
        currentRepo: repo,
      });
      
      let repoName = encodeURIComponent(repo.repo_name);
      let index = location.href.indexOf(repoName) + repoName.length;
      let path = decodeURIComponent(location.href.slice(index));
      this.setState({path: path});
      this.updateDirentList(path);
    });

    this.props.updateCurrentTab('my-libs'); // just for refersh brower;
  }
  
  updateDirentList = (filePath) => {
    let repoID = this.state.repoID;
    this.setState({isDirentListLoading: true});
    seafileAPI.listDir(repoID, filePath).then(res => {
      let direntList = res.data.map(item => {
        return new Dirent(item);
      });
      this.setState({
        isDirentListLoading: false,
        direntList: direntList,
      });
    }).catch(() => {
      this.setState({pathExist: false});
    });
  }

  onItemClick = (dirent) => {
    this.resetSelected();
    let direntPath = Utils.joinPath(this.state.path, dirent.name);
    if (dirent.isDir()) {
      this.updateDirentList(direntPath);
      this.setState({path: direntPath});

      let fileUrl = siteRoot + 'library/' + this.state.repoID + '/' + this.state.repoName + direntPath;
      window.history.pushState({url: fileUrl, path: direntPath}, direntPath, fileUrl);
    } else {
      const w=window.open('about:blank');
      const url = siteRoot + 'lib/' + this.state.repoID + '/file' + direntPath;
      w.location.href = url;
    }
  }

  onAddFolder = (dirPath) => {
    let repoID = this.state.repoID;
    seafileAPI.createDir(repoID, dirPath).then(() => {
      let name = Utils.getFileName(dirPath);
      let dirent = this.createDirent(name, 'dir');
      let direntList = this.addItem(dirent, 'dir');
      this.setState({direntList: direntList});
    });
  }
  
  onAddFile = (filePath, isDraft) => {
    let repoID = this.state.repoID;
    seafileAPI.createDir(repoID, filePath).then(() => {
      let name = Utils.getFileName(filePath);
      let dirent = this.createDirent(name, 'file');
      let direntList = this.addItem(dirent, 'file');
      this.setState({direntList: direntList});
    });
  }

  onItemDelete = (dirent) => {
    let repoID = this.state.repoID;
    let direntPath = Utils.joinPath(this.state.path, dirent.name);
    if (dirent.isDir()) {
      seafileAPI.deleteDir(repoID, direntPath).then(() => {
        let direntList = this.deleteItem(dirent);
        this.setState({direntList: direntList});
      }).catch(() => {
        // todo
      })
    } else {
      seafileAPI.deleteFile(repoID, direntPath).then(() => {
        let direntList = this.deleteItem(dirent);
        this.setState({direntList: direntList});
      }).catch(() => {
        // todo
      })
    }
  }

  onItemRename = (dirent, newName) => {
    let repoID = this.state.repoID;
    let direntPath = Utils.joinPath(this.state.path, dirent.name);
    if (dirent.isDir()) {
      seafileAPI.renameDir(repoID, direntPath, newName).then(() => {
        let direntList = this.renameItem(dirent, newName);
        this.setState({direntList: direntList});
      }).catch(() => {
        //todo
      });
    } else {
      seafileAPI.renameFile(repoID, direntPath, newName).then(() => {
        let direntList = this.renameItem(dirent, newName);
        this.setState({direntList: direntList});
      }).catch(() => {
        //todo
      });
    }
  }
  
  onItemMove = (destRepo, dirent, moveToDirentPath) => {
    let dirName = dirent.name;
    let repoID = this.state.repoID;
    seafileAPI.moveDir(repoID, destRepo.repo_id, moveToDirentPath, this.state.path, dirName).then(() => {
      
      let direntList = this.deleteItem(dirent);
      this.setState(direntList);

      let message = gettext('Successfully moved %(name)s.');
      message = message.replace('%(name)s', dirName);
      Toast.success(message);
    }).catch(() => {
      let message = gettext('Failed to move %(name)s');
      message = message.replace('%(name)s', dirName);
      Toast.error(message);
    });
  }

  onItemCopy = (destRepo, dirent, copyToDirentPath) => {
    let dirName = dirent.name;
    let repoID = this.state.repoID;
    seafileAPI.copyDir(repoID, destRepo.repo_id, copyToDirentPath, this.state.path, dirName).then(() => {
      let message = gettext('Successfully copied %(name)s.');
      message = message.replace('%(name)s', dirName);
      Toast.success(message);
    }).catch(() => {
      let message = gettext('Failed to copy %(name)s');
      message = message.replace('%(name)s', dirName);
      Toast.error(message);
    });
  }

  onItemSelected = (dirent) => {
    let direntList = this.state.direntList.map(item => {
      if (item.name === dirent.name) {
        item.isSelected = !item.isSelected;
      }
      return item;
    });
    let selectedDirentList = direntList.filter(item => {
      return item.isSelected;
    });

    if (selectedDirentList.length) {
      this.setState({isDirentSelected: true});
      if (selectedDirentList.length === direntList.length) {
        this.setState({
          isAllDirentSelected: true,
          direntList: direntList,
          selectedDirentList: selectedDirentList,
        });
      } else {
        this.setState({
          isAllDirentSelected: false,
          direntList: direntList,
          selectedDirentList: selectedDirentList
        });
      }
    } else {
      this.setState({
        isDirentSelected: false,
        isAllDirentSelected: false,
        direntList: direntList,
        selectedDirentList: []
      });
    }
  }

  onItemsMove = (destRepo, destDirentPath) => {
    let dirNames = this.getSelectedDirentNames();
    let repoID = this.state.repoID;
    seafileAPI.moveDir(repoID, destRepo.repo_id, destDirentPath, this.state.path, dirNames).then(() => {
      let direntList = this.deleteItems(dirNames);
      this.setState({direntList: direntList});
      let message = gettext('Successfully moved %(name)s.');
      message = message.replace('%(name)s', dirNames);
      Toast.success(message);
    }).catch(() => {
      let message = gettext('Failed to move %(name)s');
      message = message.replace('%(name)s', dirNames);
      Toast.error(message);
    });
  }

  onItemsCopy = (destRepo, destDirentPath) => {
    let dirNames = this.getSelectedDirentNames();
    let repoID = this.state.repoID;
    seafileAPI.copyDir(repoID, destRepo.repo_id, destDirentPath, this.state.path, dirNames).then(() => {
      let message = gettext('Successfully copied %(name)s.');
      message = message.replace('%(name)s', dirNames);
      Toast.success(message);
    }).catch(() => {
      let message = gettext('Failed to copy %(name)s');
      message = message.replace('%(name)s', dirNames);
      Toast.error(message);
    });
  }

  onItemsDelete = () => {
    let dirNames = this.getSelectedDirentNames();
    let repoID = this.state.repoID;
    seafileAPI.deleteMutipleDirents(repoID, this.state.path, dirNames).then(res => {
      let direntList = this.deleteItems(dirNames);
      this.setState({direntList: direntList});
    });
  }

  onAllItemSelected = () => {
    if (this.state.isAllDirentSelected) {
      let direntList = this.state.direntList.map(item => {
        item.isSelected = false;
        return item;
      });
      this.setState({
        isDirentSelected: false,
        isAllDirentSelected: false,
        direntList: direntList,
        selectedDirentList: [],
      });
    } else {
      let direntList = this.state.direntList.map(item => {
        item.isSelected = true;
        return item;
      });
      this.setState({
        isDirentSelected: true,
        isAllDirentSelected: true,
        direntList: direntList,
        selectedDirentList: direntList,
      });
    }
  }

  onFileTagChanged = (dirent, direntPath) => {
    let repoID = this.state.repoID;
    seafileAPI.listFileTags(repoID, direntPath).then(res => {
      let fileTags = res.data.file_tags.map(item => {
        return new FileTag(item);
      });
      this.updateDirent(dirent, 'file_tags', fileTags);
    });
  }

  onMenuClick = () => {
    this.props.onMenuClick();
  }

  onPathClick = (path) => {
    this.updateDirentList(path);
    this.setState({path: path});

    let fileUrl = siteRoot + 'library/' + this.state.repoID + '/' + this.state.repoName  + path;
    window.history.pushState({url: fileUrl, path: path}, path, fileUrl);
  }

  updateDirent = (dirent, paramKey, paramValue) => {
    let newDirentList = this.state.direntList.map(item => {
      if (item.name === dirent.name) {
        item[paramKey] = paramValue;
      }
      return item;
    });
    this.setState({direntList: newDirentList});
  }

  onFileUploadSuccess = () => {
    // todo update upload file to direntList
  }

  onSearchedClick = () => {
    // todo
  }

  resetSelected = () => {
    this.setState({isDirentSelected: false, isAllDirentSelected: false});
  }

  addItem = (dirent, type) => {
    let direntList = this.state.direntList.map(item => {return item}); //clone
    if (type === 'dir') {
      direntList.unshift(dirent);
      return direntList;
    }
    direntList.push(dirent);
    return direntList;
  }

  deleteItem = (dirent) => {
    return this.state.direntList.filter(item => {
      return item.name !== dirent.name;
    });
  }
  
  renameItem = (dirent, newName) => {
    return this.state.direntList.map(item => {
      if (item.name === dirent.name) {
        item.name = newName;
      }
      return item;
    });
  }
  
  deleteItems = (dirNames) => {
    let direntList = this.state.direntList.map(item => {return item}); //clone
    while (dirNames.length) {
      for (let i = 0; i < direntList.length; i++) {
        if (direntList[i].name === dirNames[0]) {
          direntList.splice(i, 1);
          break;
        }
      }
      dirNames.shift();
    }
    return direntList;
  }
  
  createDirent(name, type) {
    let data = new Date().getTime()/1000;
    let dirent = null;
    if (type === 'dir') {
      dirent = new Dirent({
        id: '000000000000000000',
        name: name,
        type: type,
        mtime: data,
        permission: 'rw',
      });
    } else {
      dirent = new Dirent({
        id: '000000000000000000',
        name: name,
        type: type,
        mtime: data,
        permission: 'rw',
        size: 0,
        starred: false,
        is_locked: false,
        lock_time: '',
        lock_owner: null,
        locked_by_me: false,
        modifier_name: '',
        modifier_email: '',
        modifier_contact_email: '',
        file_tags: []
      });
    }
    return dirent;
  }

  getSelectedDirentNames = () => {
    let names = [];
    this.state.selectedDirentList.forEach(selectedDirent => {
      names.push(selectedDirent.name);
    });
    return names;
  }

  isMarkdownFile(filePath) {
    let index = filePath.lastIndexOf('.');
    if (index === -1) {
      return false;
    } else {
      let type = filePath.substring(index).toLowerCase();
      if (type === '.md' || type === '.markdown') {
        return true;
      } else {
        return false;
      }
    }
  }

  render() {
    return (
      <DirPanel 
        currentRepo={this.state.currentRepo}
        path={this.state.path}
        pathExist={this.state.pathExit}
        repoID={this.state.repoID}
        repoName={this.state.repoName}
        permission={this.state.permission}
        isDirentListLoading={this.state.isDirentListLoading}
        isDirentSelected={this.state.isDirentSelected}
        isAllDirentSelected={this.state.isAllDirentSelected}
        direntList={this.state.direntList}
        selectedDirentList={this.state.direntList}
        onItemClick={this.onItemClick}
        onAddFile={this.onAddFile}
        onAddFolder={this.onAddFolder}
        onItemMove={this.onItemMove}
        onItemCopy={this.onItemCopy}
        onItemRename={this.onItemRename}
        onItemDelete={this.onItemDelete}
        onItemSelected={this.onItemSelected}
        onItemsMove={this.onItemsMove}
        onItemsCopy={this.onItemsCopy}
        onItemsDelete={this.onItemsDelete}
        onAllItemSelected={this.onAllItemSelected}
        onFileTagChanged={this.onFileTagChanged}
        onMenuClick={this.onMenuClick}
        onPathClick={this.onPathClick}
        updateDirent={this.updateDirent}
        switchViewMode={this.switchViewMode}
        onSearchedClick={this.onSearchedClick}
        onFileUploadSuccess={this.onFileUploadSuccess}
      />
    );
  }
}

DirView.propTypes = propTypes;

export default DirView;
