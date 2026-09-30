"""Script para verificar el estado de la base de datos."""
import sqlite3
import sys

try:
    conn = sqlite3.connect('app/data/omnimaillook.db')
    
    # Listar todas las tablas
    tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    print("Tablas en la BD:")
    for t in tables:
        print(f"  - {t[0]}")
    
    # Verificar si existe tabla findings
    if ('findings',) in tables:
        print("\n✓ Tabla 'findings' existe")
        count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        print(f"  Registros: {count}")
        
        # Ver estructura
        schema = conn.execute("PRAGMA table_info(findings)").fetchall()
        print("  Columnas:")
        for col in schema:
            print(f"    {col[1]} ({col[2]})")
    else:
        print("\n✗ Tabla 'findings' NO existe")
        print("  Se necesita inicializar con findings.init_findings()")
    
    conn.close()
    
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
