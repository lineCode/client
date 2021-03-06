// @flow
import * as React from 'react'
import * as DevGen from '../../actions/dev-gen'
import Render from './render'
import {connect} from 'react-redux'
import {navigateUp} from '../../actions/route-tree'
import {isTesting} from '../../local-debug'

function DumbSheet(props) {
  return (
    <Render
      onBack={props.onBack}
      onDebugConfigChange={props.onDebugConfigChange}
      dumbIndex={props.dumbIndex}
      dumbFilter={props.dumbFilter}
      dumbFullscreen={props.dumbFullscreen}
      autoIncrement={isTesting}
    />
  )
}

export default connect(
  (state: any) => ({
    dumbIndex: state.dev.dumbIndex,
    dumbFilter: state.dev.dumbFilter,
    dumbFullscreen: state.dev.dumbFullscreen,
  }),
  (dispatch: any) => ({
    onBack: () => dispatch(navigateUp()),
    onDebugConfigChange: (config: $PropertyType<DevGen.UpdateDebugConfigPayload, 'payload'>) =>
      dispatch(DevGen.createUpdateDebugConfig({...config})),
  })
)(DumbSheet)
