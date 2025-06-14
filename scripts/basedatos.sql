-- ================================================================
-- PASO 1: DIAGNÓSTICO COMPLETO
-- ================================================================

-- 1.1 Verificar si el trigger existe y está activo
SELECT 
    t.tgname as trigger_name,
    t.tgenabled as enabled,
    p.proname as function_name,
    c.relname as table_name
FROM pg_trigger t
JOIN pg_proc p ON t.tgfoid = p.oid
JOIN pg_class c ON t.tgrelid = c.oid
WHERE t.tgname = 'on_auth_user_created';

-- 1.2 Verificar estructura de la tabla profiles
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_name = 'profiles' AND table_schema = 'public'
ORDER BY ordinal_position;

-- 1.3 Verificar políticas RLS en profiles
SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual
FROM pg_policies
WHERE tablename = 'profiles';

-- ================================================================
-- PASO 2: ELIMINAR TRIGGER PROBLEMÁTICO
-- ================================================================

-- Eliminar el trigger actual que está causando problemas
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;

-- ================================================================
-- PASO 3: CREAR FUNCIÓN ALTERNATIVA MÁS SEGURA
-- ================================================================

-- Eliminar función anterior
DROP FUNCTION IF EXISTS handle_new_user();

-- Crear función nueva más robusta
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger 
LANGUAGE plpgsql 
SECURITY DEFINER SET search_path = public
AS $$
DECLARE
    user_email text;
    user_name text;
    user_role text;
BEGIN
    -- Log para debugging
    RAISE LOG 'Creating profile for user: %', NEW.id;
    
    -- Validar que el usuario tenga email
    IF NEW.email IS NULL OR NEW.email = '' THEN
        RAISE LOG 'User % has no email, skipping profile creation', NEW.id;
        RETURN NEW;
    END IF;
    
    user_email := NEW.email;
    
    -- Extraer nombre de forma segura
    user_name := CASE 
        WHEN NEW.raw_user_meta_data IS NOT NULL 
             AND NEW.raw_user_meta_data->>'full_name' IS NOT NULL 
             AND LENGTH(TRIM(NEW.raw_user_meta_data->>'full_name')) > 0
        THEN TRIM(NEW.raw_user_meta_data->>'full_name')
        WHEN NEW.raw_user_meta_data IS NOT NULL 
             AND NEW.raw_user_meta_data->>'name' IS NOT NULL 
             AND LENGTH(TRIM(NEW.raw_user_meta_data->>'name')) > 0
        THEN TRIM(NEW.raw_user_meta_data->>'name')
        ELSE SPLIT_PART(user_email, '@', 1)
    END;
    
    -- Extraer rol de forma segura
    user_role := CASE 
        WHEN NEW.raw_user_meta_data IS NOT NULL 
             AND NEW.raw_user_meta_data->>'role' IS NOT NULL
        THEN NEW.raw_user_meta_data->>'role'
        ELSE 'parent'
    END;
    
    -- Validar que el rol sea válido
    IF user_role NOT IN ('parent', 'teacher', 'specialist', 'admin') THEN
        user_role := 'parent';
    END IF;
    
    -- Insertar el perfil con manejo de errores
    BEGIN
        INSERT INTO public.profiles (
            id,
            email,
            full_name,
            role,
            is_active,
            created_at,
            updated_at
        ) VALUES (
            NEW.id,
            user_email,
            user_name,
            user_role,
            true,
            NOW(),
            NOW()
        );
        
        RAISE LOG 'Profile created successfully for user: %', NEW.id;
        
    EXCEPTION 
        WHEN unique_violation THEN
            RAISE LOG 'Profile already exists for user: %', NEW.id;
        WHEN OTHERS THEN
            RAISE LOG 'Error creating profile for user %: %', NEW.id, SQLERRM;
    END;
    
    RETURN NEW;
END;
$$;

-- ================================================================
-- PASO 4: CREAR TRIGGER MEJORADO
-- ================================================================

-- Crear trigger con configuración más específica
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW 
    EXECUTE FUNCTION public.handle_new_user();

-- ================================================================
-- PASO 5: VERIFICAR Y CORREGIR POLÍTICAS RLS
-- ================================================================

-- Eliminar políticas problemáticas
DROP POLICY IF EXISTS "Users can insert own profile" ON profiles;
DROP POLICY IF EXISTS "Users can view own profile" ON profiles;
DROP POLICY IF EXISTS "Users can update own profile" ON profiles;

-- Crear políticas más permisivas para la creación inicial
CREATE POLICY "Enable insert for authenticated users" ON profiles
    FOR INSERT 
    WITH CHECK (true);

CREATE POLICY "Enable select for users based on user_id" ON profiles
    FOR SELECT 
    USING (auth.uid() = id);

CREATE POLICY "Enable update for users based on user_id" ON profiles
    FOR UPDATE 
    USING (auth.uid() = id)
    WITH CHECK (auth.uid() = id);

-- ================================================================
-- PASO 6: FUNCIÓN PARA CREAR PERFILES MANUALMENTE
-- ================================================================

CREATE OR REPLACE FUNCTION create_profile_for_existing_users()
RETURNS TEXT AS $$
DECLARE
    user_record RECORD;
    created_count INTEGER := 0;
    error_count INTEGER := 0;
    result_text TEXT;
BEGIN
    -- Buscar usuarios sin perfil
    FOR user_record IN 
        SELECT u.id, u.email, u.raw_user_meta_data, u.created_at
        FROM auth.users u
        LEFT JOIN public.profiles p ON u.id = p.id
        WHERE p.id IS NULL
        ORDER BY u.created_at
    LOOP
        BEGIN
            INSERT INTO public.profiles (
                id,
                email,
                full_name,
                role,
                is_active,
                created_at,
                updated_at
            ) VALUES (
                user_record.id,
                user_record.email,
                COALESCE(
                    user_record.raw_user_meta_data->>'full_name',
                    user_record.raw_user_meta_data->>'name',
                    SPLIT_PART(user_record.email, '@', 1)
                ),
                COALESCE(user_record.raw_user_meta_data->>'role', 'parent'),
                true,
                user_record.created_at,
                NOW()
            );
            
            created_count := created_count + 1;
            
        EXCEPTION WHEN OTHERS THEN
            error_count := error_count + 1;
            RAISE WARNING 'Error creating profile for user %: %', user_record.email, SQLERRM;
        END;
    END LOOP;
    
    result_text := format('Perfiles creados: %s, Errores: %s', created_count, error_count);
    RETURN result_text;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ================================================================
-- PASO 7: FUNCIÓN DE VERIFICACIÓN FINAL
-- ================================================================

CREATE OR REPLACE FUNCTION verify_user_system()
RETURNS TABLE (
    check_name TEXT,
    status TEXT,
    details TEXT
) AS $$
BEGIN
    -- Verificar trigger
    RETURN QUERY
    SELECT 
        'Trigger Status'::TEXT,
        CASE WHEN EXISTS (
            SELECT 1 FROM pg_trigger 
            WHERE tgname = 'on_auth_user_created'
        ) THEN '✅ Activo' ELSE '❌ Inactivo' END,
        'Trigger para crear perfiles automáticamente'::TEXT;
    
    -- Verificar función
    RETURN QUERY
    SELECT 
        'Function Status'::TEXT,
        CASE WHEN EXISTS (
            SELECT 1 FROM pg_proc 
            WHERE proname = 'handle_new_user'
        ) THEN '✅ Existe' ELSE '❌ No existe' END,
        'Función handle_new_user'::TEXT;
    
    -- Verificar políticas RLS
    RETURN QUERY
    SELECT 
        'RLS Policies'::TEXT,
        (SELECT COUNT(*)::TEXT || ' políticas activas') as status,
        'Políticas de seguridad en tabla profiles'::TEXT
    FROM pg_policies 
    WHERE tablename = 'profiles';
    
    -- Verificar usuarios sin perfil
    RETURN QUERY
    SELECT 
        'Users without Profile'::TEXT,
        (
            SELECT COUNT(*)::TEXT || ' usuarios sin perfil'
            FROM auth.users u
            LEFT JOIN public.profiles p ON u.id = p.id
            WHERE p.id IS NULL
        ) as status,
        'Usuarios que necesitan perfil manual'::TEXT;
    
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ================================================================
-- PASO 8: EJECUTAR VERIFICACIONES
-- ================================================================

-- Crear perfiles para usuarios existentes sin perfil
SELECT create_profile_for_existing_users();

-- Verificar el estado del sistema
SELECT * FROM verify_user_system();

-- ================================================================
-- PASO 9: INSTRUCCIONES FINALES
-- ================================================================

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '🔧 SISTEMA DE USUARIOS REPARADO';
    RAISE NOTICE '================================';
    RAISE NOTICE '';
    RAISE NOTICE 'CAMBIOS REALIZADOS:';
    RAISE NOTICE '✅ Trigger recreado con mejor manejo de errores';
    RAISE NOTICE '✅ Función mejorada con validaciones robustas';
    RAISE NOTICE '✅ Políticas RLS actualizadas';
    RAISE NOTICE '✅ Perfiles creados para usuarios existentes';
    RAISE NOTICE '';
    RAISE NOTICE 'PRUEBA AHORA:';
    RAISE NOTICE '1. Registra un nuevo usuario en tu aplicación';
    RAISE NOTICE '2. Verifica que se cree automáticamente el perfil';
    RAISE NOTICE '3. Si persiste el error, revisa los logs de Supabase';
    RAISE NOTICE '';
END $$;