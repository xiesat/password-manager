plugins {
    id("org.jetbrains.kotlin.jvm")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    // 用当前 JDK 编译、产出 Java 17 字节码（避免强制要求本机安装 JDK 17 toolchain）
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // Android 平台自带 org.json；纯 JVM 运行时由调用方提供。
    compileOnly("org.json:json:20240303")
    testImplementation("org.json:json:20240303")
}

/** 运行跨语言黄金向量校验（无需 Android SDK）。 */
tasks.register<JavaExec>("specVectors") {
    group = "verification"
    description = "运行 spec/*.json 中的跨语言测试向量"
    mainClass.set("com.pmvault.core.SpecVectorsKt")
    classpath = sourceSets.test.get().runtimeClasspath
    args(rootProject.projectDir.parentFile.absolutePath)
}
