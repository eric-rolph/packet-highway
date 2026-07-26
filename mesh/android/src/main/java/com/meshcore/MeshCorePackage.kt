package com.meshcore

import com.facebook.react.TurboReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.model.ReactModuleInfo
import com.facebook.react.module.model.ReactModuleInfoProvider

/**
 * Autolinked by RN. `TurboReactPackage` works on both architectures: on the old
 * one it behaves like a lazy `ReactPackage`, on the new one it feeds the
 * TurboModule registry.
 */
class MeshCorePackage : TurboReactPackage() {

    override fun getModule(name: String, context: ReactApplicationContext): NativeModule? =
        if (name == MeshCoreModule.NAME) MeshCoreModule(context) else null

    override fun getReactModuleInfoProvider() = ReactModuleInfoProvider {
        mapOf(
            MeshCoreModule.NAME to ReactModuleInfo(
                MeshCoreModule.NAME,
                MeshCoreModule.NAME,
                /* canOverrideExistingModule = */ false,
                /* needsEagerInit = */ true,   // must exist before JS calls installJSI()
                /* isCxxModule = */ false,
                /* isTurboModule = */ true,
            )
        )
    }
}
